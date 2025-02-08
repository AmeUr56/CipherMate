import pyfiglet
from rich.progress import Progress
import time

def ascii_banner(text,font="standard",width=80,justify="center"):
    banner = pyfiglet.figlet_format(
        text=text,
        font=font,
        width=width,
        justify=justify,
    )
    
    return banner

def progress_bar(total=100,advance=10):
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing...", total=total)

        for _ in range(total//advance):
            time.sleep(0.05)
            progress.update(task, advance=advance)