import sysv_ipc

mq_in = sysv_ipc.MessageQueue(5)
mq_out = sysv_ipc.MessageQueue(10)

def recv():
    if mq_out.current_messages:
        return str(mq_out.receive(block=True, type=11)[0])[2:-1]
    return ''

def send(s):
    mq_in.send(s, block=True, type=11)
