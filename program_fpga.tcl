
set bitfile [lindex $argv 0]
if { [llength $argv] > 1 } {
    set jtag_cable [lindex $argv 1]
} else {
    set jtag_cable 0
}

open_hw
connect_hw_server
current_hw_target [lindex [get_hw_targets] ${jtag_cable}]
open_hw_target
current_hw_device [lindex [get_hw_devices] 0]
refresh_hw_device -update_hw_probes false [lindex [get_hw_devices] 0]
set_property PROBES.FILE {} [lindex [get_hw_devices] 0]
set_property PROGRAM.FILE ${bitfile} [lindex [get_hw_devices] 0]
program_hw_devices [lindex [get_hw_devices] 0]
refresh_hw_device [lindex [get_hw_devices] 0]
close_hw_target
disconnect_hw_server
