#!/usr/bin/env python3
"""
pasm_compiler.py — компилятор ассемблера "pasm" в реальный 16-битный
x86 машинный код (загрузочный сектор для QEMU).

ГРАММАТИКА PASM
-----------------------------------------------------------
; комментарий — от ';' до конца строки

org <число>          — режим сборки:
                          1000h / 1000h0  -> boot-образ для QEMU (флоппи)
                          109h  / 109h0   -> .exe для DOS/DOSBox
push <число>          — открывающая "рамка" файла (декоративная)
post <число>          — закрывающая "рамка" файла (декоративная)

section .data          — начало сегмента данных
    имя db 'строка' ...     — переменная-строка (лишние токены после
                               строки декоративны и игнорируются)
    'ещё строка' ...          — строка БЕЗ имени сразу после предыдущей
                               db-строки продолжает предыдущую переменную
                               (склеивается через перевод строки)
    Строка всегда автоматически завершается нулевым байтом.

section .text          — начало сегмента кода
<имя>:                  — метка
jmp <метка>[:]          — безусловный переход
mov <reg>, <imm|метка>  — загрузка регистра числом ИЛИ адресом переменной
                          (reg: AX или BX)

st <reg>  /  "st: <reg>"
    — читать СТРОКУ с клавиатуры посимвольно (эхо на экран через
      BIOS int 10h) до Enter, положить АДРЕС введённой строки в reg.

ПЕЧАТЬ СТРОКИ:
    mov <reg>, имя_переменной   ; адрес строки в reg
    mov <reg>, 10h0             ; << сразу после, тот же регистр —
                                   печатает строку из reg посимвольно
                                   (BIOS int 10h до нулевого байта)
Во всех остальных случаях "mov reg, 10h0" — обычная загрузка числа.

cmp <reg>, <метка>       — СРАВНИВАЕТ строку, на которую указывает reg,
                          со строкой-переменной <метка> (побайтово).
                          Дальше идёт БЛОК КОДА С БОЛЬШИМ ОТСТУПОМ —
                          он выполняется, ТОЛЬКО ЕСЛИ строки совпали.
                          Блок закрывается словом 'end' на том же
                          (большом) отступе.

end                     — на отступе тела cmp-блока: закрывает блок
                          сравнения.
                          на отступе тела метки: конец программы
                          (после — авто-зависание, чтобы CPU не улетел
                          в данные).

add <reg>, <imm|reg>     — reg = reg + значение
sub <reg>, <imm|reg>     — reg = reg - значение
mul <reg>                — AX = AX * reg   (старшая половина результата в DX)
div <reg>                — AX = AX / reg, DX = остаток (DX перед делением
                          обнуляется автоматически)

call <метка>             — вызов подпрограммы (переход с запоминанием
                          адреса возврата)
ret                       — возврат из подпрограммы (на call)

ДВУХСТУПЕНЧАТАЯ ЗАГРУЗКА (автоматически, без директив):
    Если скомпилированная программа не влезает в один сектор (510 байт),
    компилятор САМ добавляет крошечный первый сектор-загрузчик, который
    дочитывает остальные секторы с дискеты и передаёт им управление.
    Пользователю ничего для этого писать не нужно — просто пишешь код,
    лимит в 510 байт для собственно программы снят (до ~9 КБ).

Числа: десятичные (10) или шестнадцатеричные (10h / 10h0).
"""

import re
import sys

def strip_comment_keep_indent(line: str) -> str:
    idx = line.find(';')
    return line if idx == -1 else line[:idx]


def is_number_token(tok: str) -> bool:
    tok = tok.strip().rstrip(':').strip()
    return bool(re.fullmatch(r'([0-9A-Fa-f]+)h0?', tok) or re.fullmatch(r'[0-9]+', tok))


def parse_number(tok: str) -> int:
    tok = tok.strip().rstrip(':').strip()
    m = re.fullmatch(r'([0-9A-Fa-f]+)h0?', tok)
    if m:
        return int(m.group(1), 16)
    return int(tok, 10)


def encode_pasm_string(text: str) -> bytes:
    """Кодирует строку pasm в байты, обрабатывая escape-последовательности:
       \\n -> перевод строки (0x0D 0x0A, CR+LF — понимает BIOS teletype)
       \\t -> табуляция (0x09)
       \\\\ -> обратный слэш
    """
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == 'n':
                out += b'\r\n'
                i += 2
                continue
            elif nxt == 't':
                out += b'\x09'
                i += 2
                continue
            elif nxt == '\\':
                out += b'\\'
                i += 2
                continue
        out += ch.encode('ascii')
        i += 1
    return bytes(out)


SUPPORTED_REGS = {'AX', 'BX', 'CX', 'DX'}
MOV_OPCODE = {'AX': 0xB8, 'BX': 0xBB, 'CX': 0xB9, 'DX': 0xBA}
REG_CODE = {'AX': 0, 'CX': 1, 'DX': 2, 'BX': 3}  # для ModRM
SI_TRANSFER = {'AX': bytes([0x89, 0xC6]), 'BX': bytes([0x89, 0xDE])}  # mov si, reg
BX_TRANSFER = {'AX': bytes([0x89, 0xC3]), 'BX': b''}                  # mov bx, reg (empty if already bx)
INPUT_BUFFER_ADDR = 0x0500  # свободная область низкой памяти для буфера ввода строки

BOOT_LOAD_ADDR = 0x7C00     # сектор 1 — крошечный загрузчик (генерируется автоматически)
STAGE2_LOAD_ADDR = 0x7E00   # сюда грузится настоящая программа пользователя
EXE_LOAD_ADDR = 0x0000       # .exe: адреса всегда относительно начала сегмента кода
EXE_INBUF_SIZE = 128         # свой буфер под ввод строки внутри .exe (вместо физич. 0x0500)
SECTOR_SIZE = 512
MAX_EXTRA_SECTORS = 18      # безопасный предел для одного BIOS int13h-чтения (одна дорожка)


class PasmError(Exception):
    pass


class Instr:
    def __init__(self, kind, **kw):
        self.kind = kind
        self.__dict__.update(kw)
        self.addr = None
        self.size = self._compute_size()

    def _compute_size(self):
        k = self.kind
        if k == 'prologue':
            return 13
        if k == 'jmp_near':
            return 3
        if k == 'mov_reg_imm16':
            return 3
        if k == 'mov_reg_reg':
            return 2
        if k == 'read_line':
            return 22 if getattr(self, 'mode', 'qemu') == 'console' else 26
        if k == 'print_string':
            base = 15 if getattr(self, 'mode', 'qemu') == 'console' else 13
            return base if self.reg == 'BX' else base + 2
        if k == 'cmp_str':
            return 2 + 6 * len(self.data)   # mov si,reg + N*(cmp+jne)
        if k == 'label':
            return 0
        if k == 'halt_loop':
            return 2
        if k == 'prologue_exe':
            return 6
        if k == 'dos_exit':
            return 4
        if k == 'cls':
            return 6
        if k == 'call_near':
            return 3
        if k == 'ret':
            return 1
        if k == 'arith_imm':      # add/sub reg, imm16
            return 4
        if k == 'arith_reg':      # add/sub reg, reg
            return 2
        if k == 'mul':            # mul reg   (AX = AX * reg)
            return 2
        if k == 'div':            # div reg   (AX,DX = AX / reg, ост.)
            return 4              # xor dx,dx (2) + div reg (2)
        raise PasmError(f"неизвестный вид инструкции: {k}")


class DataVar:
    def __init__(self, name, data):
        self.name = name
        self.data = data
        self.addr = None


def compile_pasm(src: str):
    raw_lines = [strip_comment_keep_indent(l) for l in src.splitlines()]

    mode = None
    seen_org = False
    seen_text_section = False
    state = 'pre'

    labels = {}
    data_vars = {}
    data_order = []
    cur_var_name = None
    cur_var_pieces = None

    program = []
    jmp_targets = []      # [(Instr(jmp_near), target_name)]
    cmp_jumps = []         # [(Instr(cmp_str) -- resolved at codegen, uses skip_label)]
    cond_stack = []         # stack of (cmp_indent:int, skip_label:str)
    auto_label_n = 0

    def finalize_current_var():
        nonlocal cur_var_name, cur_var_pieces
        if cur_var_name is not None:
            out = bytearray()
            for idx, piece in enumerate(cur_var_pieces):
                if idx > 0:
                    out += b'\r\n'          # склейка отдельных строк-продолжений
                out += encode_pasm_string(piece)   # + обработка \n внутри самой строки
            out += b'\x00'
            data_vars[cur_var_name] = DataVar(cur_var_name, bytes(out))
            data_order.append(cur_var_name)
        cur_var_name, cur_var_pieces = None, None

    for lineno, rawfull in enumerate(raw_lines, 1):
        stripped = rawfull.strip()
        if not stripped:
            continue
        indent = len(rawfull) - len(rawfull.lstrip(' '))

        parts = stripped.split(None, 1)
        head = parts[0]
        rest = parts[1].strip() if len(parts) > 1 else ''
        headl = head.lower().rstrip(':')

        # --- directives ---------------------------------------------------
        if headl == 'org':
            val = parse_number(rest)
            if val == 0x1000:
                mode = 'qemu'
            elif val == 0x109:
                mode = 'console'
            else:
                raise PasmError(f"строка {lineno}: неизвестный режим org {rest!r}")
            seen_org = True
            continue

        if headl == 'push' and state == 'pre':
            continue

        if headl == 'post':
            break

        if stripped.lower().startswith('section'):
            sect = stripped.lower().replace(' ', '')
            if '.data' in sect:
                finalize_current_var()
                state = 'data'
            elif '.text' in sect:
                finalize_current_var()
                state = 'code'
                seen_text_section = True
                program.append(Instr('prologue_exe' if mode == 'console' else 'prologue'))
            else:
                raise PasmError(f"строка {lineno}: неизвестная секция {stripped!r}")
            continue

        # --- 'end' : либо закрывает cmp-блок (если есть открытый и отступ
        #     этой строки больше отступа cmp), либо завершает программу ---
        if headl == 'end':
            if cond_stack and indent > cond_stack[-1][0]:
                cmp_indent, skip_label = cond_stack.pop()
                marker = Instr('label')
                labels[skip_label] = marker
                program.append(marker)
            else:
                state = 'ended'
            continue

        # если инструкция идёт без явного 'section .text' — считаем, что
        # секция .text началась неявно, сразу после org/push
        if state == 'pre' and headl in ('jmp', 'mov', 'st', 'cmp', 'cls') or \
           (state == 'pre' and stripped.endswith(':') and ' ' not in stripped.rstrip(':').strip()):
            state = 'code'
            seen_text_section = True
            program.append(Instr('prologue_exe' if mode == 'console' else 'prologue'))

        if state == 'ended':
            continue

        # --- data section ---------------------------------------------------
        if state == 'data':
            m = re.match(r"^(\w+)\s+db\s+'([^']*)'", stripped)
            if m:
                finalize_current_var()
                cur_var_name, cur_var_pieces = m.group(1), [m.group(2)]
                continue
            m2 = re.match(r"^'([^']*)'", stripped)
            if m2:
                if cur_var_name is None:
                    raise PasmError(f"строка {lineno}: строка без переменной перед ней: {stripped!r}")
                cur_var_pieces.append(m2.group(1))
                continue
            raise PasmError(f"строка {lineno}: ожидалась строка данных, получено {stripped!r}")

        if state != 'code':
            continue

        # --- label definition: "name:" alone on the line --------------------
        if stripped.endswith(':') and ' ' not in stripped.rstrip(':').strip() and \
           head.rstrip(':').lower() not in ('jmp', 'mov', 'st', 'cmp', 'push', 'post', 'org', 'end',
                                              'add', 'sub', 'mul', 'div', 'call', 'ret', 'cls'):
            name = stripped.rstrip(':').strip()
            marker = Instr('label')
            labels[name] = marker
            program.append(marker)
            continue

        # --- instructions -----------------------------------------------------
        if headl == 'jmp':
            target = rest.rstrip(':').strip()
            ins = Instr('jmp_near')
            program.append(ins)
            jmp_targets.append((ins, target))
            continue

        if headl == 'mov':
            reg, val = [p.strip() for p in rest.split(',', 1)]
            reg = reg.rstrip(':').upper()
            if reg not in SUPPORTED_REGS:
                raise PasmError(f"строка {lineno}: регистр {reg} не поддерживается")
            val = val.rstrip(':').strip()
            if is_number_token(val):
                num = parse_number(val)
                if num == 0x11:
                    # "mov reg, 11h0" — мгновенный триггер: очистить экран
                    program.append(Instr('cls'))
                    continue
                if num == 0x10:
                    # "mov reg, 10h0" — мгновенный триггер: напечатать
                    # строку, на которую сейчас указывает reg (не важно,
                    # где reg был загружен — хоть в этой же строке выше,
                    # хоть в вызывающем коде до call)
                    program.append(Instr('print_string', reg=reg, mode=mode))
                    continue
                ins = Instr('mov_reg_imm16', reg=reg, value=num)
            elif val.upper() in SUPPORTED_REGS:
                ins = Instr('mov_reg_reg', dst=reg, src=val.upper())
            else:
                if val not in data_vars:
                    raise PasmError(f"строка {lineno}: неизвестная переменная {val!r}")
                ins = Instr('mov_reg_imm16', reg=reg, value=('ref', val))
            program.append(ins)
            continue

        if headl == 'st':
            reg = rest.rstrip(':').strip().upper()
            if reg not in SUPPORTED_REGS:
                raise PasmError(f"строка {lineno}: регистр {reg} не поддерживается для st")
            program.append(Instr('read_line', reg=reg, mode=mode))
            continue

        if headl == 'cls':
            program.append(Instr('cls'))
            continue

        if headl == 'cmp':
            reg, val = [p.strip() for p in rest.split(',', 1)]
            reg = reg.rstrip(':').upper()
            val = val.rstrip(':').strip()
            if reg not in SUPPORTED_REGS:
                raise PasmError(f"строка {lineno}: регистр {reg} не поддерживается")
            if val not in data_vars:
                raise PasmError(f"строка {lineno}: cmp поддерживает только сравнение со строковой переменной, {val!r} не найдена")
            auto_label_n += 1
            skip_label = f'__endif_{auto_label_n}'
            ins = Instr('cmp_str', reg=reg, data=data_vars[val].data, skip_label=skip_label)
            program.append(ins)
            cond_stack.append((indent, skip_label))
            continue

        if headl in ('add', 'sub'):
            reg, val = [p.strip() for p in rest.split(',', 1)]
            reg = reg.rstrip(':').upper()
            val = val.rstrip(':').strip()
            if reg not in SUPPORTED_REGS:
                raise PasmError(f"строка {lineno}: регистр {reg} не поддерживается")
            if is_number_token(val):
                ins = Instr('arith_imm', op=headl, reg=reg, value=parse_number(val))
            elif val.upper() in SUPPORTED_REGS:
                ins = Instr('arith_reg', op=headl, dst=reg, src=val.upper())
            else:
                raise PasmError(f"строка {lineno}: {headl} принимает число или регистр, получено {val!r}")
            program.append(ins)
            continue

        if headl == 'mul':
            reg = rest.rstrip(':').strip().upper()
            if reg not in SUPPORTED_REGS:
                raise PasmError(f"строка {lineno}: регистр {reg} не поддерживается")
            program.append(Instr('mul', reg=reg))
            continue

        if headl == 'div':
            reg = rest.rstrip(':').strip().upper()
            if reg not in SUPPORTED_REGS:
                raise PasmError(f"строка {lineno}: регистр {reg} не поддерживается")
            program.append(Instr('div', reg=reg))
            continue

        if headl == 'call':
            target = rest.rstrip(':').strip()
            ins = Instr('call_near')
            program.append(ins)
            jmp_targets.append((ins, target))
            continue

        if headl == 'ret':
            program.append(Instr('ret'))
            continue

        raise PasmError(f"строка {lineno}: не могу разобрать: {stripped!r}")

    finalize_current_var()

    if not seen_org:
        raise PasmError("отсутствует директива 'org'")
    if not seen_text_section:
        raise PasmError("отсутствует 'section .text'")
    if mode not in ('qemu', 'console'):
        raise PasmError("режим org не распознан")

    # ---- "mov reg,10h0"/"mov reg,11h0" уже превращены в print_string/cls
    #      прямо при разборе (см. выше) ------------------------------------

    if mode == 'console':
        # .exe-программа завершается возвратом в DOS, а не зависанием
        program.append(Instr('dos_exit'))
        # свой буфер под ввод строки — физический 0x0500 небезопасен под DOS
        data_vars['__inbuf'] = DataVar('__inbuf', bytes(EXE_INBUF_SIZE))
        data_order.append('__inbuf')
    else:
        program.append(Instr('halt_loop'))

    # ---- address resolution -------------------------------------------
    addr = STAGE2_LOAD_ADDR if mode == 'qemu' else EXE_LOAD_ADDR
    for ins in program:
        ins.addr = addr
        addr += ins.size
    for name in data_order:
        dv = data_vars[name]
        dv.addr = addr
        addr += len(dv.data)

    for ins, target in jmp_targets:
        if target not in labels:
            raise PasmError(f"неизвестная метка: {target}")

    code = bytearray()
    for ins in program:
        k = ins.kind
        if k == 'label':
            continue
        elif k == 'prologue':
            code += bytes([0xFA])
            code += bytes([0x31, 0xC0])
            code += bytes([0x8E, 0xD8])
            code += bytes([0x8E, 0xC0])
            code += bytes([0x8E, 0xD0])
            code += bytes([0xBC]) + (0x7C00).to_bytes(2, 'little')
            code += bytes([0xFB])
        elif k == 'prologue_exe':
            # DOS не гарантирует DS=ES=CS для .exe (в отличие от .com) —
            # выставляем сами, иначе обращения к своим переменным (msg,
            # help и т.д.) полезут не в тот сегмент.
            code += bytes([0x8C, 0xC8])   # mov ax, cs
            code += bytes([0x8E, 0xD8])   # mov ds, ax
            code += bytes([0x8E, 0xC0])   # mov es, ax
        elif k == 'mov_reg_imm16':
            if isinstance(ins.value, tuple) and ins.value[0] == 'ref':
                value = data_vars[ins.value[1]].addr
            else:
                value = ins.value
            code += bytes([MOV_OPCODE[ins.reg]]) + (value & 0xFFFF).to_bytes(2, 'little')
        elif k == 'mov_reg_reg':
            modrm = 0xC0 | (REG_CODE[ins.dst] << 3) | REG_CODE[ins.src]
            code += bytes([0x8B, modrm])   # mov dst, src
        elif k == 'arith_imm':
            digit = 0 if ins.op == 'add' else 5   # /0=ADD, /5=SUB
            modrm = 0xC0 | (digit << 3) | REG_CODE[ins.reg]
            code += bytes([0x81, modrm]) + (ins.value & 0xFFFF).to_bytes(2, 'little')
        elif k == 'arith_reg':
            opcode = 0x01 if ins.op == 'add' else 0x29   # ADD r/m,r16 / SUB r/m,r16
            modrm = 0xC0 | (REG_CODE[ins.src] << 3) | REG_CODE[ins.dst]
            code += bytes([opcode, modrm])
        elif k == 'mul':
            modrm = 0xC0 | (4 << 3) | REG_CODE[ins.reg]   # F7 /4 = MUL r/m16 (AX = AX*reg, DX:AX)
            code += bytes([0xF7, modrm])
        elif k == 'div':
            code += bytes([0x31, 0xD2])   # xor dx, dx  (обнуляем старшую половину делимого)
            modrm = 0xC0 | (6 << 3) | REG_CODE[ins.reg]   # F7 /6 = DIV r/m16 (DX:AX / reg -> AX,ост.DX)
            code += bytes([0xF7, modrm])
        elif k == 'call_near':
            target_name = dict((id(i), t) for i, t in jmp_targets)[id(ins)]
            target_addr = labels[target_name].addr
            next_ip = ins.addr + ins.size
            disp = (target_addr - next_ip) & 0xFFFF
            code += bytes([0xE8]) + disp.to_bytes(2, 'little')
        elif k == 'ret':
            code += bytes([0xC3])
        elif k == 'read_line':
            if ins.mode == 'console':
                inbuf_addr = data_vars['__inbuf'].addr
                code += bytes([0xBB]) + inbuf_addr.to_bytes(2, 'little')  # mov bx, буфер
                code += bytes([0xB4, 0x01])   # loop: mov ah, 01h   ; DOS: читать+эхо сама
                code += bytes([0xCD, 0x21])   #       int 21h
                code += bytes([0x3C, 0x0D])   #       cmp al, 0x0D (Enter)
                code += bytes([0x74, 0x05])   #       je done
                code += bytes([0x88, 0x07])   #       mov [bx], al
                code += bytes([0x43])         #       inc bx
                code += bytes([0xEB, 0xF3])   #       jmp loop
                code += bytes([0xC6, 0x07, 0x00])  # done: mov byte [bx], 0
                code += bytes([MOV_OPCODE[ins.reg]]) + inbuf_addr.to_bytes(2, 'little')
            else:
                code += bytes([0xBB]) + INPUT_BUFFER_ADDR.to_bytes(2, 'little')  # mov bx, 0x0500
                code += bytes([0xB4, 0x00])   # loop: mov ah, 0
                code += bytes([0xCD, 0x16])   #       int 16h
                code += bytes([0x3C, 0x0D])   #       cmp al, 0x0D (Enter)
                code += bytes([0x74, 0x09])   #       je done
                code += bytes([0x88, 0x07])   #       mov [bx], al
                code += bytes([0x43])         #       inc bx
                code += bytes([0xB4, 0x0E])   #       mov ah, 0eh
                code += bytes([0xCD, 0x10])   #       int 10h
                code += bytes([0xEB, 0xEF])   #       jmp loop
                code += bytes([0xC6, 0x07, 0x00])  # done: mov byte [bx], 0
                code += bytes([MOV_OPCODE[ins.reg]]) + INPUT_BUFFER_ADDR.to_bytes(2, 'little')
        elif k == 'print_string':
            code += BX_TRANSFER[ins.reg]  # mov bx, reg  (пусто если reg уже BX)
            if ins.mode == 'console':
                code += bytes([0x8A, 0x07])   # loop: mov al, [bx]
                code += bytes([0x3C, 0x00])   #       cmp al, 0
                code += bytes([0x74, 0x09])   #       je done
                code += bytes([0x8A, 0xD0])   #       mov dl, al
                code += bytes([0xB4, 0x02])   #       mov ah, 02h   ; DOS: вывод символа
                code += bytes([0xCD, 0x21])   #       int 21h
                code += bytes([0x43])         #       inc bx
                code += bytes([0xEB, 0xF1])   #       jmp loop
            else:
                code += bytes([0x8A, 0x07])   # loop: mov al, [bx]
                code += bytes([0x3C, 0x00])   #       cmp al, 0
                code += bytes([0x74, 0x07])   #       je done
                code += bytes([0xB4, 0x0E])   #       mov ah, 0eh
                code += bytes([0xCD, 0x10])   #       int 10h
                code += bytes([0x43])         #       inc bx
                code += bytes([0xEB, 0xF3])   #       jmp loop
        elif k == 'cmp_str':
            code += SI_TRANSFER[ins.reg]  # mov si, reg
            skip_addr = labels[ins.skip_label].addr
            for offset, ch in enumerate(ins.data):
                next_after_jne = ins.addr + 2 + offset * 6 + 6
                disp = (skip_addr - next_after_jne) & 0xFF
                code += bytes([0x80, 0x7C, offset & 0xFF, ch])  # cmp byte [si+offset], ch
                code += bytes([0x75, disp])                       # jne skip
        elif k == 'halt_loop':
            code += bytes([0xEB, 0xFE])
        elif k == 'dos_exit':
            code += bytes([0xB4, 0x4C])   # mov ah, 4Ch  ; DOS: завершить программу
            code += bytes([0xCD, 0x21])   # int 21h
        elif k == 'cls':
            code += bytes([0xB4, 0x00])   # mov ah, 0
            code += bytes([0xB0, 0x03])   # mov al, 3      ; текстовый режим 80x25, очищает экран
            code += bytes([0xCD, 0x10])   # int 10h
        elif k == 'jmp_near':
            target_name = dict((id(i), t) for i, t in jmp_targets)[id(ins)]
            target_addr = labels[target_name].addr
            next_ip = ins.addr + ins.size
            disp = (target_addr - next_ip) & 0xFFFF
            code += bytes([0xE9]) + disp.to_bytes(2, 'little')
        else:
            raise PasmError(f"кодогенерация не реализована для {k}")

    for name in data_order:
        code += data_vars[name].data

    if mode == 'console':
        return build_exe(bytes(code))

    # ---- stage 2: программа пользователя, дополняется до целого числа
    #      секторов -----------------------------------------------------
    stage2 = bytes(code)
    num_sectors = (len(stage2) + SECTOR_SIZE - 1) // SECTOR_SIZE
    if num_sectors < 1:
        num_sectors = 1
    if num_sectors > MAX_EXTRA_SECTORS:
        raise PasmError(
            f"программа слишком большая: {len(stage2)} байт "
            f"({num_sectors} секторов) — в этой версии компилятор умеет "
            f"грузить не больше {MAX_EXTRA_SECTORS} секторов одним BIOS-запросом"
        )
    stage2 += bytes(num_sectors * SECTOR_SIZE - len(stage2))

    # ---- stage 1: крошечный загрузчик в самом boot-секторе — читает
    #      num_sectors секторов с дискеты сразу за собой и передаёт
    #      туда управление. Генерируется автоматически, пользователь его
    #      не пишет и не видит. ------------------------------------------
    loader = bytearray()
    loader += bytes([0xFA])                                       # cli
    loader += bytes([0x31, 0xC0])                                   # xor ax,ax
    loader += bytes([0x8E, 0xD8])                                    # mov ds,ax
    loader += bytes([0x8E, 0xC0])                                     # mov es,ax
    loader += bytes([0x8E, 0xD0])                                      # mov ss,ax
    loader += bytes([0xBC]) + (0x7C00).to_bytes(2, 'little')           # mov sp,0x7c00
    loader += bytes([0xFB])                                            # sti
    loader += bytes([0xB4, 0x02])                                       # mov ah, 02h  (читать секторы)
    loader += bytes([0xB0, num_sectors & 0xFF])                          # mov al, N
    loader += bytes([0xB5, 0x00])                                        # mov ch, 0    (цилиндр 0)
    loader += bytes([0xB1, 0x02])                                        # mov cl, 2    (сектор 2 — сразу после boot)
    loader += bytes([0xB6, 0x00])                                        # mov dh, 0    (голова 0)
    # dl уже содержит номер загрузочного диска, полученный от BIOS — не трогаем
    loader += bytes([0xBB]) + STAGE2_LOAD_ADDR.to_bytes(2, 'little')      # mov bx, 0x7E00
    loader += bytes([0xCD, 0x13])                                         # int 13h
    loader += bytes([0x72, 0x05])                                          # jc disk_error (+5)
    loader += bytes([0xEA, 0x00, 0x7E, 0x00, 0x00])                         # jmp 0000:7E00
    loader += bytes([0xEB, 0xFE])                                           # disk_error: jmp $

    if len(loader) > 510:
        raise PasmError("внутренняя ошибка: загрузчик не помещается в boot-сектор")
    loader += bytes(510 - len(loader))
    loader += bytes([0x55, 0xAA])

    return bytes(loader) + stage2


def build_exe(code: bytes) -> bytes:
    """Собирает минимальный DOS .exe (заголовок MZ + один сегмент кода/данных)."""
    HEADER_SIZE = 32  # 2 параграфа

    total_size = HEADER_SIZE + len(code)
    cp = (total_size + 511) // 512
    cblp = total_size % 512
    if cblp == 0:
        cblp = 512

    header = bytearray(HEADER_SIZE)
    header[0:2] = b'MZ'
    header[2:4] = cblp.to_bytes(2, 'little')
    header[4:6] = cp.to_bytes(2, 'little')
    header[6:8] = (0).to_bytes(2, 'little')          # e_crlc: релокаций нет
    header[8:10] = (2).to_bytes(2, 'little')          # e_cparhdr: заголовок = 2 параграфа
    header[10:12] = (0).to_bytes(2, 'little')          # e_minalloc
    header[12:14] = (0xFFFF).to_bytes(2, 'little')      # e_maxalloc: взять сколько дадут
    header[14:16] = (0).to_bytes(2, 'little')            # e_ss: тот же сегмент, что и код
    header[16:18] = (0xFFFE).to_bytes(2, 'little')        # e_sp: вершина сегмента
    header[18:20] = (0).to_bytes(2, 'little')              # e_csum: не проверяется
    header[20:22] = (0).to_bytes(2, 'little')               # e_ip: код с самого начала
    header[22:24] = (0).to_bytes(2, 'little')                # e_cs: тот же сегмент
    header[24:26] = (0x1C).to_bytes(2, 'little')              # e_lfarlc
    header[26:28] = (0).to_bytes(2, 'little')                  # e_ovno

    return bytes(header) + code


def main():
    if len(sys.argv) != 3:
        print("Использование: python3 pasm_compiler.py вход.pasm выход.img")
        sys.exit(1)
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        src = f.read()
    try:
        binary = compile_pasm(src)
    except PasmError as e:
        print(f"Ошибка компиляции: {e}")
        sys.exit(1)
    with open(sys.argv[2], 'wb') as f:
        f.write(binary)
    print(f"OK: собрано {len(binary)} байт -> {sys.argv[2]}")


if __name__ == '__main__':
    main()
