import os
import threading
import time
import webbrowser

os.environ.setdefault("SIGMA_FORGE_HOST", "127.0.0.1")
os.environ.setdefault("SIGMA_FORGE_PORT", "8000")


def _open():
    time.sleep(2)
    webbrowser.open(f"http://127.0.0.1:{os.environ['SIGMA_FORGE_PORT']}")


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()
    import uvicorn

    from app.main import app

    if os.environ.get("SIGMA_FORGE_NO_BROWSER") != "1":
        threading.Thread(target=_open, daemon=True).start()
    uvicorn.run(app, host=os.environ["SIGMA_FORGE_HOST"], port=int(os.environ["SIGMA_FORGE_PORT"]))
