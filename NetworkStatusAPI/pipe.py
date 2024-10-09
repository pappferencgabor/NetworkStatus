import json
import random
import win32pipe
import win32file
import pywintypes

jsonTypes = json.load(open("types.json"))

def server():
    pipeName = 'CsServer'
    
    pipe = win32pipe.CreateNamedPipe(
        r'\\.\pipe\\' + pipeName,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 65536, 65536, 0, None
    )
    print("Várakozás kliens kapcsolódására...")
    win32pipe.ConnectNamedPipe(pipe, None)
    print("Kliens kapcsolódott!")

    try:
        response = random.choice(jsonTypes['types'])
        win32file.WriteFile(pipe, response.encode('utf-8'))

    except pywintypes.error as e:
        if e.args[0] == 109:
            print("A pipe lezárult (hiba 109).")

    finally:
        win32file.CloseHandle(pipe)

if __name__ == "__main__":
    while True:
        server()
