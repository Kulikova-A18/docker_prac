import random
import subprocess
from time import sleep


def script_runner(cmd: str) -> str:
    try:
        subprocess.run(cmd.split(' '),
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,
                       check=True)
        return f'{cmd.split("/")[-1].split(" ")[0]} executed'
    except subprocess.CalledProcessError:
        return f'Error during {cmd.split("/")[-1].split(" ")[0]} execution'


if __name__ == '__main__':

    SCRIPTS_POOL = ['exploit.sh', 'normal.sh']

    while True:
        print(script_runner(cmd = f'bash scripts/{random.choice(SCRIPTS_POOL)} 10.10.0.2'))
        sleep(1)
