from win10toast import ToastNotifier

def harmful_alert(proc_name):
    t = ToastNotifier()
    t.show_toast(
        proc_name,
        "Detected as harmful.",
        duration=5,
        threaded=True
    )

def core_run_completed():
    t = ToastNotifier()
    t.show_toast(
        "Completed",
        "ProCatch run completed.",
        duration=10,
        threaded=True
    )

def initial_run_completed():
    t = ToastNotifier()
    t.show_toast(
        "Completed",
        "Initial Whitelist generated.",
        duration=10,
        threaded=True
    )