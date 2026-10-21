"""One inert child that requires the reviewed supervisor's SIGKILL branch."""
import signal

signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print('CONTROL_CHILD_READY_IGNORES_INT_TERM', flush=True)
while True:
    signal.pause()
