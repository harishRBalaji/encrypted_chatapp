#!/usr/bin/env python3
from datetime import datetime
from typing import List, Tuple
from uuid import uuid4

from nicegui import ui
from Crypto.Cipher import AES

messages: List[Tuple[str, str, str, str, bytes]] = []
key = b'Sixteen byte key'

@ui.refreshable
def chat_messages(own_id: str) -> None:
    if messages:
        for user_id, avatar, ctext, stamp, nonce in messages:
            decryptor = AES.new(key, AES.MODE_EAX, nonce=nonce)
            text = decryptor.decrypt(ctext).decode('utf-8')

            ui.chat_message(text=text, stamp=stamp, avatar=avatar, sent=own_id == user_id)
    else:
        ui.label('No messages yet').classes('mx-auto my-36')
    ui.run_javascript('window.scrollTo(0, document.body.scrollHeight)')


@ui.page('/')
async def main():
    def send() -> None:
        stamp = datetime.now().strftime('%X')
        ctx, tag = user_cipher.encrypt_and_digest(text.value.encode("utf-8"))
        messages.append((user_id, avatar, ctx, stamp, nonce))
        text.value = ''
        chat_messages.refresh()

    user_id = str(uuid4())
    avatar = f'https://robohash.org/{user_id}?bgset=bg2'
    user_cipher = AES.new(key, AES.MODE_EAX)
    nonce = user_cipher.nonce


    ui.add_css(r'a:link, a:visited {color: inherit !important; text-decoration: none; font-weight: 500}')
    with ui.footer().classes('bg-white'), ui.column().classes('w-full max-w-3xl mx-auto my-6'):
        with ui.row().classes('w-full no-wrap items-center'):
            with ui.avatar().on('click', lambda: ui.navigate.to(main)):
                ui.image(avatar)
            text = ui.input(placeholder='message').on('keydown.enter', send) \
                .props('rounded outlined input-class=mx-3').classes('flex-grow')
        ui.markdown('simple chat app built with [NiceGUI](https://nicegui.io)') \
            .classes('text-xs self-end mr-8 m-[-1em] text-primary')

    await ui.context.client.connected()  # chat_messages(...) uses run_javascript which is only possible after connecting
    with ui.column().classes('w-full max-w-2xl mx-auto items-stretch'):
        chat_messages(user_id)


if __name__ in {'__main__', '__mp_main__'}:
    ui.run()