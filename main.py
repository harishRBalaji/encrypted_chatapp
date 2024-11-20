from nicegui import ui
from datetime import datetime
from Crypto.Cipher import AES
import sqlite3
import uuid
import os

# Database setup
connection = sqlite3.connect('chatapp.db', check_same_thread=False)
cursor = connection.cursor()

# Create table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
    user_id TEXT, 
    avatar TEXT, 
    message BLOB, 
    timestamp TEXT, 
    nonce BLOB)''')

connection.commit()

# Securely fetch encryption key (use environment variable or a secrets manager in production)
key = os.getenv('AES_KEY', b'Sixteen byte key')  # Must be 16, 24, or 32 bytes long

# Global message store
messages = []

# Session-specific message store
session_messages = []

@ui.refreshable
def chat_messages(own_id: str) -> None:
    """Dynamically refresh chat messages."""
    if session_messages:  # Show only session-specific messages
        for user_id, avatar, ctext, stamp, nonce in session_messages:
            decryptor = AES.new(key, AES.MODE_EAX, nonce=nonce)
            text = decryptor.decrypt(ctext).decode('utf-8')
            ui.chat_message(
                text=text,
                stamp=stamp,
                avatar=avatar,
                sent=own_id == user_id
            )
    else:
        ui.label('No messages yet').classes('mx-auto my-36')
    ui.run_javascript('window.scrollTo(0, document.body.scrollHeight)')

@ui.page('/')
async def main():
    """Main page for the chat application."""
    user_id = str(uuid.uuid4())  # Generate a unique user ID
    avatar = f'https://robohash.org/{user_id}?bgset=bg2'  # Generate a unique avatar

    def send() -> None:
        """Encrypt and send a message."""
        if not text.value.strip():
            return  # Do not send empty messages

        cipher = AES.new(key, AES.MODE_EAX)  # Create a new cipher object for each message
        nonce = cipher.nonce
        timestamp = datetime.now().strftime('%X')
        ctext, tag = cipher.encrypt_and_digest(text.value.encode("utf-8"))

        # Add message to session and global stores
        session_messages.append((user_id, avatar, ctext, timestamp, nonce))
        messages.append((user_id, avatar, ctext, timestamp, nonce))

        # Save the message to the database
        save_message_to_db(user_id, avatar, ctext, timestamp, nonce)

        text.value = ''
        chat_messages.refresh()

    def save_message_to_db(user_id, avatar, message, timestamp, nonce):
        """Save a message to the SQLite database."""
        try:
            cursor.execute(
                "INSERT INTO messages (user_id, avatar, message, timestamp, nonce) VALUES (?, ?, ?, ?, ?)",
                (user_id, avatar, message, timestamp, nonce)
            )
            connection.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    # Load all messages from the database into global store
    try:
        cursor.execute("SELECT user_id, avatar, message, timestamp, nonce FROM messages")
        db_messages = cursor.fetchall()
        messages.extend((row[0], row[1], row[2], row[3], row[4]) for row in db_messages)
    except sqlite3.Error as e:
        print(f"Database error during load: {e}")

    # Render the UI
    ui.add_css(r'a:link, a:visited {color: inherit !important; text-decoration: none; font-weight: 500}')
    with ui.footer().classes('bg-white'), ui.column().classes('w-full max-w-3xl mx-auto my-6'):
        with ui.row().classes('w-full no-wrap items-center'):
            with ui.avatar():
                ui.image(avatar).classes('w-10 h-10')  # Render user avatar
            text = ui.input(placeholder='message').on('keydown.enter', send) \
                .props('rounded outlined input-class=mx-3').classes('flex-grow')
        ui.markdown('simple chat app built with [NiceGUI](https://nicegui.io)') \
            .classes('text-xs self-end mr-8 m-[-1em] text-primary')

    await ui.context.client.connected()  # Ensure connection for JavaScript execution
    with ui.column().classes('w-full max-w-2xl mx-auto items-stretch'):
        chat_messages(user_id)

if __name__ in {'__main__', '__mp_main__'}:
    ui.run()