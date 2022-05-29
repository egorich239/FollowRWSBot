#!/usr/bin/python3

import argparse
import itertools
import json
import logging
import os
import sys
import urllib

from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
from typing import List, Optional, Set

from telegram import constants, Update, Message
from telegram.ext import filters, ApplicationBuilder, CallbackContext, CommandHandler, MessageHandler

from url_normalize import url_normalize


@dataclass_json
@dataclass
class WebhookConfig:
    hostname: str
    path: str
    address: str = "0.0.0.0"
    port: int = field(default_factory=lambda: int(os.environ["PORT"]))
    

@dataclass_json
@dataclass
class Config:
    token: str
    warning: str
    blocklist: str
    webhook: Optional[WebhookConfig] = None


def _make_argparser() -> argparse.ArgumentParser:
  p = argparse.ArgumentParser(description="Bot aimed at directing spammers to follow the Russian Warship")
  p.add_argument("-k", metavar="<config file>", type=str, required=True)
  return p

def _host(url: str) -> str:
    url = url_normalize(url)
    return urllib.parse.urlparse(url).netloc

def _collect_all_links(msg: Message) -> Set[str]:
    res: Set[str] = set()
    for e in itertools.chain(msg.entities, msg.caption_entities):
        if e.type == "url":
            res.add(_host(msg.parse_entity(e)))
        elif e.type == "text_link":
            res.add(_host(e.url))
        elif e.type == "mention":
            res.add(msg.parse_entity(e).lower())
    return res

class Bot:
    def __init__(self, cfg: Config) -> None:
        self._cfg: Config = cfg
        self._blocklist: Set[str] = set()
        self._load_blocklist()
        self._store_blocklist()

    def _load_blocklist(self) -> None:
        with open(self._cfg.blocklist) as f:
            self._blocklist = set(f.read().splitlines())

    def _store_blocklist(self) -> None:
        with open(self._cfg.blocklist, "w", newline="\n") as f:
            f.write("".join(f"{e}\n" for e in sorted(self._blocklist)))

    async def _handle_scam(
            self,
            context: CallbackContext.DEFAULT_TYPE,
            chat_id: int, message_from: int, reply_to: int):
        admins = await context.bot.get_chat_administrators(chat_id)
        admin_ids = [a.user.id for a in admins]
        if context.bot.id in admin_ids:
            logging.info("Admin mode: deleting the message")
            await context.bot.delete_message(chat_id=chat_id, message_id=reply_to)
        else:
            logging.info("Canary mode: issuing a warning")
            await context.bot.send_message(chat_id=chat_id, text=self._cfg.warning, reply_to_message_id=reply_to)


    async def _handle_message(self, update: Update, context: CallbackContext.DEFAULT_TYPE):
        links = set()
        for msg in [update.message, update.edited_message]:
            if msg is not None and msg.from_user is not None:
                message_from = msg.from_user.id
                reply_to = msg.message_id
                links |= _collect_all_links(msg)
                break
        isec = links & self._blocklist
        if len(isec):
            logging.info("Message mentions blocked content: " + " ".join(sorted(isec)))
            await self._handle_scam(context, update.effective_chat.id, message_from, reply_to)


    def start(self):
        app = ApplicationBuilder().token(self._cfg.token).build()
        app.add_handler(MessageHandler(filters.ALL, self._handle_message))
        if self._cfg.webhook is None:
            logging.info("Starting in polling mode")
            app.run_polling()
        else:
            webhook_url = f"{self._cfg.webhook.hostname}/{self._cfg.webhook.path}"
            addr = self._cfg.webhook.address
            port = self._cfg.webhook.port
            logging.info(f"Starting webhook at {webhook_url}; backend at {addr}:{port}")
            app.run_webhook(
                listen=addr, port=port, url_path=self._cfg.webhook.path, webhook_url=webhook_url)


def main(args: List[str]) -> None:
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )

    _args: argparse.Namespace = _make_argparser().parse_args(args[1:])

    with open(_args.k, "r") as config:
        cfg_str = config.read()
    cfg: Config = Config.schema().loads(cfg_str)

    b: Bot = Bot(cfg)
    b.start()

if __name__ == "__main__":
  main(sys.argv)
