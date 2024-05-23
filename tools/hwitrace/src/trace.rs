/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
 *
 * This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
 *
 * M3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * M3 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 */

use crate::error::Error;
use crate::instrs::Instruction;

use regex::Regex;

use std::collections::HashMap;
use std::io::{self, BufRead, Lines, StdinLock};

pub fn enrich_trace(instrs: &HashMap<usize, Instruction>) -> Result<(), Error> {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let Some(first) = lines.next()
    else {
        return Ok(());
    };

    if first?.contains("Rocket") {
        rocket_trace(instrs, lines)
    }
    else {
        rv32_trace(instrs, lines)
    }
}

fn rocket_trace(
    instrs: &HashMap<usize, Instruction>,
    lines: Lines<StdinLock<'_>>,
) -> Result<(), Error> {
    println!("Legend:");
    println!(" <n>:    <PC>     <opcode>  p e i      <cause>         <tval>   <disassembly>\n");
    println!(" p = privilege level");
    println!(" e = exception");
    println!(" i = interrupt\n");

    let re = Regex::new(r"^\s*\d+: 0x([0-9a-f]+) 0x([0-9a-f]+) \d \d \d 0x[0-9a-f]+ 0x[0-9a-f]+")
        .unwrap();

    let mut last_symbol = String::new();
    let mut last_binary = String::new();

    for line in lines {
        let line = line?;
        let line = line.trim_end();

        //   12: 0x10000b24 0x01a93023 1 0 0 0x0000000000000005 0x00000000
        if let Some(m) = re.captures(line) {
            let addr = usize::from_str_radix(m.get(1).unwrap().as_str(), 16)?;
            let _opcode = usize::from_str_radix(m.get(2).unwrap().as_str(), 16)?;

            if let Some(instr) = instrs.get(&addr) {
                if instr.symbol != last_symbol || instr.binary != last_binary {
                    println!("\x1B[1m{}\x1B[0m - {}:", instr.binary, instr.symbol);
                    last_symbol = instr.symbol.clone();
                    last_binary = instr.binary.clone();
                }

                println!("{} {}", line, instr.disasm);
            }
            else {
                println!("{} ??", line);
            }
        }
    }

    Ok(())
}

fn rv32_trace(
    instrs: &HashMap<usize, Instruction>,
    lines: Lines<StdinLock<'_>>,
) -> Result<(), Error> {
    println!("Legend:");
    println!("   ?<payload> |   <PC>   | <opcode> | <diassembly>\n");
    println!("   ?<payload> can be:");
    println!("    > : branch; payload = target address");
    println!("    @ : ld/st ; payload = address");
    println!("    = : other ; payload = ALU result\n");

    let mut last_symbol = String::new();
    let mut last_binary = String::new();

    let mut pc: i32 = -1;
    let mut last_irq = false;

    for line in lines {
        let line = line?;

        let raw_data = u64::from_str_radix(&line.replace("x", "0"), 16)?;
        let payload = (raw_data & 0xffffffff) as u32;
        let irq_active = (raw_data & 0x800000000) != 0;
        let is_addr = (raw_data & 0x200000000) != 0;
        let is_branch = (raw_data & 0x100000000) != 0;

        let info = format!(
            "{} {}{:08x}",
            if irq_active || last_irq { "IRQ" } else { "   " },
            if is_branch {
                ">"
            }
            else if is_addr {
                "@"
            }
            else {
                "="
            },
            payload
        );

        if irq_active && !last_irq {
            pc = 0x10;
        }

        if pc >= 0 {
            if let Some(instr) = instrs.get(&(pc as usize)) {
                if instr.symbol != last_symbol || instr.binary != last_binary {
                    println!("\x1B[1m{}\x1B[0m - {}:", instr.binary, instr.symbol);
                    last_symbol = instr.symbol.clone();
                    last_binary = instr.binary.clone();
                }

                let mut opname = instr
                    .disasm
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();

                if instr.opcode == 0x0400000b {
                    opname = "retirq".to_string();
                }

                if is_branch
                    && ![
                        "j", "jal", "jr", "jalr", "ret", "retirq", "beq", "bne", "blt", "ble",
                        "bge", "bgt", "bltu", "bleu", "bgeu", "bgtu", "beqz", "bnez", "blez",
                        "bgez", "bltz", "bgtz",
                    ]
                    .contains(&opname.as_str())
                {
                    println!(
                        "{} ** UNEXPECTED BRANCH DATA FOR INSN AT {:08x}! **",
                        info, pc
                    );
                }

                if is_addr
                    && !["lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"]
                        .contains(&opname.as_str())
                {
                    println!(
                        "{} ** UNEXPECTED ADDR DATA FOR INSN AT {:08x}! **",
                        info, pc
                    );
                }

                let opcode_fmt = if (instr.opcode & 3) == 3 {
                    format!("{:08x}", instr.opcode)
                }
                else {
                    format!("    {:04x}", instr.opcode)
                };
                println!("{} | {:08x} | {} | {}", info, pc, opcode_fmt, instr.disasm);

                if !is_addr {
                    pc += if (instr.opcode & 3) == 3 { 4 } else { 2 };
                }
            }
            else {
                println!("{} ** NO INFORMATION ON INSN AT {:08x}! **", info, pc);
                pc = -1;
            }
        }
        else {
            if is_branch {
                println!("{} ** FOUND BRANCH AND STARTING DECODING **", info);
            }
            else {
                println!("{} ** SKIPPING DATA UNTIL NEXT BRANCH **", info);
            }
        }

        if is_branch {
            pc = payload as i32;
        }

        last_irq = irq_active;
    }
    Ok(())
}
