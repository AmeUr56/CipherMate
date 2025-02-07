import pyfiglet

def ascii_banner(text,font="standard",width=80,justify="center"):
    banner = pyfiglet.figlet_format(
        text=text,
        font=font,
        width=width,
        justify=justify,
    )
    
    return banner

