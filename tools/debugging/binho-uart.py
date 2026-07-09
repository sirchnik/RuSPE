import sys
import termios
import tty
import os

from binhopulsar.pulsar import Pulsar
import binhopulsar.commands.uart.definitions as uart_defs

__msg_id = 0


def msg_id():
    global __msg_id
    __msg_id += 1
    return __msg_id


def process_event(event: dict, system_msg: dict | None):
    if event["command"] == "SYS GET DEVICE INFO":
        if event["result"] not in [
            "SUCCESS",
        ]:
            raise Exception(f"Error device-info event: {event}")
        return
    if event["command"] == "UART INIT":
        if event["result"] not in [
            "INTERFACE_ALREADY_INITIALIZED",
            "SUCCESS",
        ]:
            raise Exception(f"Error init event: {event}")
        return
    if event["command"] == "UART SET VOLTAGE":
        if event["result"] not in [
            "INTERFACE_ALREADY_INITIALIZED",
            "SUCCESS",
        ]:
            raise Exception(f"Error set voltage event: {event}")
        return

    if event["command"] == "UART RECEIVE NOTIFICATION":
        payload = event["payload"]
        ascii_string = "".join(chr(x) for x in payload)
        print(ascii_string)
        return
    if event["command"] == "UART SEND":
        if event["result"] not in [
            "SUCCESS",
        ]:
            print(f"Error send event: {event}")
        return
    print(event)


dev = Pulsar()

res = dev.open()
if res["opcode"] != 0:
    raise Exception(f"Failed to open device: {res}")
res = dev.onEvent(process_event)
if res["opcode"] != 0:
    raise Exception(f"Failed to set event handler: {res}")
res = dev.getDeviceInfo(msg_id())
if res["opcode"] != 0:
    raise Exception(f"Failed to get device info: {res}")


res = dev.uartInit(
    baudrate=uart_defs.UartBaudRate.UART_BAUD_115200,
    id=msg_id(),
    dataSize=uart_defs.UartDataSize.UART_8BIT_BYTE,
    parityMode=uart_defs.UartParity.UART_NO_PARITY,
    hardwareHandshake=False,
    stopBit=uart_defs.UartStopBit.UART_ONE_STOP_BIT,
)
if res["opcode"] != 0:
    raise Exception(f"Failed to initialize UART: {res}")

print("UART initialized. Ctrl+C to exit.")
fd = sys.stdin.fileno()
old_term_attrs = termios.tcgetattr(fd)
try:
    tty.setcbreak(fd)
    escape_mode = False
    while True:
        ch = sys.stdin.read(1)
        if ch == "":
            continue
            
        if escape_mode:
            escape_mode = False
            if ch == '\x01':
                # Send actual C-a
                pass
            elif ch == '\x08' or ch == 'h': # C-a C-h or C-a h
                print("\r\n\r\n*** Picocom commands (all prefixed by [C-a])\r\n")
                print("*** [C-x] : Exit picocom\r")
                print("*** [C-h] : Show this help\r")
                print("*** [C-r] : Restart connection\r")
                print("*** [C-a] : Send C-a\r\n")
                continue
            elif ch == '\x18' or ch == 'x': # C-a C-x or C-a x
                print("\r\n*** Exiting ***\r\n")
                break
            elif ch == '\x12' or ch == 'r': # C-a C-r or C-a r
                print("\r\n*** Restarting connection ***\r\n")
                dev.close()
                termios.tcsetattr(fd, termios.TCSADRAIN, old_term_attrs)
                os.execv(sys.executable, [sys.executable] + sys.argv)
            else:
                print(f"\r\n*** Unknown command: {repr(ch)} ***\r\n")
                continue
        else:
            if ch == '\x01':
                escape_mode = True
                continue

        send_res = dev.uartSendMessage(
            id=msg_id(),
            data=[ord(ch)],
        )
        if send_res["opcode"] != 0:
            print(f"UART send failed: {send_res}\r")
except KeyboardInterrupt:
    print("\r\nExiting.\r")
except EOFError:
    print("\r\nExiting.\r")
finally:
    termios.tcsetattr(fd, termios.TCSADRAIN, old_term_attrs)
    dev.close()
