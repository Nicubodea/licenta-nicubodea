from logichandler import *

lh = LogicHandler()



while True:
    x = input()

    if x == "a":
        lh.print_timelines()
    elif x == "b":
        lh.print_alert_timelines()
    elif x == "c":
        t = int(input())
        lh.print_one_timeline(t)
    elif x == "d":
        t = int(input())
        lh.print_one_alert_timeline(t)
    pass

