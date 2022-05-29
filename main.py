#!/usr/bin/python3

import argparse
import datetime
import enum
import itertools
import logging
import os
import sys
import urllib

from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, CatchAll, Undefined
from typing import Any, Dict, List, Optional, Set

from telegram import constants, Update, Message
from telegram.ext import filters, ApplicationBuilder, CallbackContext, CommandHandler, \
    MessageHandler

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
    filters: List[Dict[str, Any]]
    webhook: Optional[WebhookConfig] = None
    log_level: str = "INFO"


@enum.unique
class Verdict(enum.IntEnum):
    SAFE = 0
    QUESTIONABLE = 10
    SCAM = 20


@dataclass
class FilterResult:
    verdict: Verdict
    explanation: Optional[List[str]] = None

    @classmethod
    def empty(cls):
        return cls(Verdict.SAFE)

    def append(self, other: "FilterResult") -> "FilterResult":
        v = max(self.verdict, other.verdict)
        if self.explanation or other.explanation:
            e = (self.explanation or []) + (other.explanation or [])
        else:
            e = None
        return FilterResult(v, explanation=e)

    def __str__(self):
        res = f"{self.verdict.name}"
        if self.explanation:
            res += " based on the following evidence:" + "".join(f"\n{e}" for e in self.explanation)
        return res


@dataclass
class BlocklistFilter:
    blocklist: Set[str]

    @classmethod
    def from_config(cls, filename: str):
        with open(filename, "r") as f:
            res = cls(set(f.read().splitlines()))
        logging.info(f"Blocklist: {res.blocklist}")
        return res

    def assess(self, update: Update):
        links = set()
        for msg in [update.message, update.edited_message]:
            if msg is not None and msg.from_user is not None:
                message_from = msg.from_user.id
                reply_to = msg.message_id
                links |= _collect_all_links(msg)
                break
        isec = links & self.blocklist
        if len(isec):
            return FilterResult(
                verdict=Verdict.SCAM, explanation=["Message mentions blocked content: " + " ".join(
                    sorted(isec))])
        return FilterResult(Verdict.SAFE)


FILTERS = {"blocklist": BlocklistFilter, }


def _make_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Bot aimed at directing spammers to follow the Russian Warship")
    p.add_argument("-k", metavar="<config file>", type=str, required=True)
    return p


def _host(url: str) -> str:
    url = url_normalize(url)
    return urllib.parse.urlparse(url).netloc


def _collect_all_links(msg: Message) -> Set[str]:
    res: Set[str] = set()
    for e in itertools.chain(msg.entities, msg.caption_entities):
        if e.type == "url":
            link = msg.parse_entity(e)
            logging.debug(f"Extracted URL: {link}")
            res.add(_host(link))
        elif e.type == "text_link":
            link = e.url
            logging.debug(f"Extracted text link: {link}")
            res.add(_host(link))
        elif e.type == "mention":
            mention = msg.parse_entity(e).lower()
            logging.debug(f"Extracted mention: {mention}")
            res.add(mention)
    return res


class Bot:
    def __init__(self, cfg: Config) -> None:
        self._cfg: Config = cfg
        self._blocklist: Set[str] = set()
        self._filters = self._load_filters()
        self._last_post: Optional[datetime.datetime] = None

    def _load_filters(self):
        res = []
        for f in self._cfg.filters:
            clname = f["filter"]
            parms = {k: v for k, v in f.items() if k != "filter"}
            res.append(FILTERS[clname].from_config(**parms))
        return res

    async def _handle_scam(
            self, context: CallbackContext.DEFAULT_TYPE, chat_id: int, message_from: int,
            reply_to: int):
        admins = await context.bot.get_chat_administrators(chat_id)
        admin_ids = [a.user.id for a in admins]
        if context.bot.id in admin_ids:
            logging.info("Admin mode: deleting the message")
            await context.bot.delete_message(chat_id=chat_id, message_id=reply_to)
        else:
            now = datetime.datetime.now()
            if self._last_post is not None and (now - self._last_post).total_seconds() < 60:
                logging.info("Canary mode: throttled a warning")
            else:
                logging.info("Canary mode: issuing a warning")
                await context.bot.send_message(
                    chat_id=chat_id, text=self._cfg.warning, reply_to_message_id=reply_to)
                self._last_post = now

    async def _handle_message(self, update: Update, context: CallbackContext.DEFAULT_TYPE):
        if update.message is None and update.edited_message is None:
            return

        msg = update.message or update.edited_message

        verdict = FilterResult.empty()
        for f in self._filters:
            verdict = verdict.append(f.assess(update))

        logging.info(f"Verdict: {verdict}")

        if verdict.verdict == Verdict.SCAM:
            await self._handle_scam(
                context, update.effective_chat.id, msg.from_user.id, msg.message_id)

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
    _args: argparse.Namespace = _make_argparser().parse_args(args[1:])

    with open(_args.k, "r") as config:
        cfg_str = config.read()
    cfg: Config = Config.schema().loads(cfg_str)
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=cfg.log_level)

    b: Bot = Bot(cfg)
    b.start()


if __name__ == "__main__":
    main(sys.argv)
