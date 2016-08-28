
# https://bitbucket.org/techtonik/hexdump/src/0263306fb87e19bddd870d31ebee6703a7c6541c/hexdump.py?fileviewer=file-view-default


import lldb
import json
import time
import binascii
import shlex
import optparse

# http://web.mit.edu/darwin/src/modules/xnu/osfmk/man/mach_msg_header.html
#
#    mach_msg_return_t
#    mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify)
#        mach_msg_header_t *msg;
#        mach_msg_option_t option;
#        mach_msg_size_t send_size;
#        mach_msg_size_t rcv_size;
#        mach_port_t rcv_name;
#        mach_msg_timeout_t timeout;
#        mach_port_t notify;

port_name = None
port_num = None
thread_state = dict()
output_file = open("mach_shark", "w")

def print_mach_msg(frame, bp_loc, dict):
    thread = frame.GetThread()
    process = thread.GetProcess()
    registers = frame.GetRegisters()
    target = process.GetTarget()
    debugger = target.GetDebugger()

    tid = thread.GetThreadID()

    x0_data = long(registers[0].GetChildAtIndex(0).GetValue(), 16)
    x1_opt = registers[0].GetChildAtIndex(1).GetValue()
    x2_len = long(registers[0].GetChildAtIndex(2).GetValue(), 16)
    x3_recv_len = long(registers[0].GetChildAtIndex(3).GetValue(), 16)
    x4_recv_name = long(registers[0].GetChildAtIndex(4).GetValue(), 16)
    x5_timeout = long(registers[0].GetChildAtIndex(5).GetValue(), 16)
    x5_notify = long(registers[0].GetChildAtIndex(6).GetValue(), 16)

    thread_state[str(tid)] = {
        'x0_data': x0_data,
        'x3_recv_len': x3_recv_len        
    }

    output = {
        'type': 'msg_send_start',
        'time': int(time.time()*1000),
        'frame': str(frame),
        'tid': tid,
        'send_msg_size': x2_len,
        'recv_msg_size': x3_recv_len,
        'msg_options': x1_opt,
        'rcv_name': x4_recv_name,
        'timeout': x5_timeout,
        'notify': x5_notify
    }

    data = None

    if(x2_len > 0):
        err = lldb.SBError()
        data = process.ReadMemory(x0_data, x2_len, err)

        output['msg'] = binascii.hexlify(data)

    output = json.dumps(output)
    output_file.write(output)
    output_file.write('\n')

    print output


def print_mach_msg_end(frame, bp_loc, dict):
    thread = frame.GetThread()
    process = thread.GetProcess()
    registers = frame.GetRegisters()
    target = process.GetTarget()
    debugger = target.GetDebugger()
    
    tid = thread.GetThreadID()
    tids = str(tid)

    output = {
        'type': 'msg_send_end',
        'time': int(time.time()*1000),
        'frame': str(frame),
        'tid': tid,
    }

    if(tids in thread_state):
        tstate = thread_state[tids]
        
        x0_data = tstate['x0_data']
        x3_recv_len = tstate['x3_recv_len']
        x0_ret = long(registers[0].GetChildAtIndex(0).GetValue(), 16)
        output['return'] = x0_ret

        data = None

        if(x3_recv_len > 0):
            err = lldb.SBError()
            data = process.ReadMemory(x0_data, x3_recv_len, err)
            output['msg'] = binascii.hexlify(data)

    output_file.write(json.dumps(output))
    output_file.write('\n')

look_up_states = {}

def rocketbootstrap_look_up(frame, bp_loc, dict):
    global port_name
    global look_up_states

    thread = frame.GetThread()
    process = thread.GetProcess()
    registers = frame.GetRegisters()
    target = process.GetTarget()
    debugger = target.GetDebugger()

    tid = thread.GetThreadID()
    tids = str(tid)

    x1_name = long(registers[0].GetChildAtIndex(1).GetValue(), 16)
    x2_ret_addr = long(registers[0].GetChildAtIndex(2).GetValue(), 16)


    error = lldb.SBError()
    port = process.ReadCStringFromMemory(x1_name, 256, error)
    if error.Success():
        print 'port name: %s, looking for %s' % (port, port_name)
     
        if(port == port_name):
            if(tid not in look_up_states):
                look_up_states[tid] = []

            look_up_states[tid].append({
                'port': port,
                'ret_addr': x2_ret_addr
            })
    else:
        print 'port name error: ', error



def rocketbootstrap_look_up_end(frame, bp_loc, dict):
    global port_name
    global look_up_states

    thread = frame.GetThread()
    process = thread.GetProcess()
    registers = frame.GetRegisters()
    target = process.GetTarget()
    debugger = target.GetDebugger()

    tid = thread.GetThreadID()
    
    if(tid in look_up_states):
        state = look_up_states[tid].pop()

        error = lldb.SBError()
        port_id = process.ReadUnsignedFromMemory(state['ret_addr'], 4, error)

        if error.Success():
            print "FOUND PORT: %s=%x" % (state['port'], port_id)

            if(len(look_up_states[tid]) == 0):
                start_sniff_port(debugger, port_id)
        else:
            print 'port id error: ', error
    else:
        print "end with no state"

def start_sniff_port(debugger, port_number):
    target = debugger.GetSelectedTarget()

    msg_bp = target.BreakpointCreateByName('mach_msg', 'libsystem_kernel.dylib')

    msg_bp.SetScriptCallbackFunction('mach_sniff.print_mach_msg')
    msg_bp.SetCondition("*(uint32_t*)($x0 + 8) == %d" % port_number)
    print msg_bp

    if False:
        for bp in msg_bp:
            insts = target.ReadInstructions(bp.GetAddress(), 100)
            first_ret = [i.GetAddress().GetLoadAddress(target) for i in insts if i.GetMnemonic(target) == 'ret']

            if(len(first_ret) > 0):
                msg_bp_end = target.BreakpointCreateByAddress(first_ret[0])
                msg_bp_end.SetScriptCallbackFunction('mach_sniff.print_mach_msg_end')

                print msg_bp_end

        process = target.GetProcess()

        debugger.SetAsync(False)
        while process.IsValid():
            print 'Continued'
            process.Continue()


def start_sniffer(debugger, command, result, internal_dict):
    global port_name

    command_args = shlex.split(command)
    parser = optparse.OptionParser(prog='start_sniffer')
    (options, args) = parser.parse_args(command_args)

    # global
    port_name = args[0]
    print 'sniffing port: %s' % port_name

    target = debugger.GetSelectedTarget()

    bs_look2 = target.BreakpointCreateByName('bootstrap_look_up2', 'libxpc.dylib')
    bs_look2.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up')
    for bp in bs_look2:
        insts = target.ReadInstructions(bp.GetAddress(), 100)
        first_ret = [i.GetAddress().GetLoadAddress(target) for i in insts if i.GetMnemonic(target) == 'ret']

        if(len(first_ret) > 0):
            bs_look2_end = target.BreakpointCreateByAddress(first_ret[0])
            bs_look2_end.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up_end')

            print bs_look2_end

    # set on rocket if available, otherwise regular crashes.
    bs_look3 = target.BreakpointCreateByName('rocketbootstrap_look_up', 'librocketbootstrap.dylib')
    if(not bs_look3.IsValid()):
        bs_look3 = target.BreakpointCreateByName('bootstrap_look_up3', 'libxpc.dylib')

    bs_look3.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up')
    for bp in bs_look3:
        insts = target.ReadInstructions(bp.GetAddress(), 200)
        first_ret = [i.GetAddress().GetLoadAddress(target) for i in insts if i.GetMnemonic(target) == 'ret']

        if(len(first_ret) > 0):
            bs_look3_end = target.BreakpointCreateByAddress(first_ret[0])
            bs_look3_end.SetScriptCallbackFunction('mach_sniff.rocketbootstrap_look_up_end')

            print bs_look3_end

    process = target.GetProcess()

    debugger.SetAsync(False)
    while process.IsValid():
        process.Continue()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f %s.start_sniffer start_sniffer' % __name__)  
    
    print 'The "start_sniffer" python command has been installed and is ready for use.'


