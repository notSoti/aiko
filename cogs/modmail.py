import asyncio
import re
from datetime import datetime, timezone
import datetime
from socket import MSG_DONTROUTE
from random_word import Wordnik
import random
import string
import os
import aiohttp
import io
import sys
import traceback
import json
from random import randint, choice
import urllib.parse
from os import system
from itertools import zip_longest
import typing
from typing import Optional, Union, List, Tuple, Literal
from types import SimpleNamespace
from git import RemoteProgress, Repo

import discord
from discord.ext import commands
from discord.ext.commands.view import StringView
from discord.ext.commands.cooldowns import BucketType
from discord.role import Role
from discord.utils import escape_markdown

from dateutil import parser

from core import checks
from core.models import DMDisabled, PermissionLevel, SimilarCategoryConverter, getLogger
from core.paginator import EmbedPaginatorSession
from core.thread import Thread
from core.time import UserFriendlyTime, human_timedelta
from core.utils import *

logger = getLogger(__name__)


class Modmail(commands.Cog):
    """Commands directly related to Modmail functionality."""

    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @trigger_typing
    @checks.has_permissions(PermissionLevel.OWNER)
    async def setup(self, ctx):
        """
        Sets up a server for Modmail.

        You only need to run this command
        once after configuring Modmail.
        """

        if ctx.guild != self.bot.modmail_guild:
            return await ctx.send(f"You can only setup in the Modmail guild: {self.bot.modmail_guild}.")

        if self.bot.main_category is not None:
            logger.debug("Can't re-setup server, main_category is found.")
            return await ctx.send(f"{self.bot.modmail_guild} is already set up.")

        if self.bot.modmail_guild is None:
            embed = discord.Embed(
                title="Error",
                description="Modmail functioning guild not found.",
                color=self.bot.error_color,
            )
            return await ctx.send(embed=embed)

        overwrites = {
            self.bot.modmail_guild.default_role: discord.PermissionOverwrite(read_messages=False),
            self.bot.modmail_guild.me: discord.PermissionOverwrite(read_messages=True),
        }

        for level in PermissionLevel:
            if level <= PermissionLevel.REGULAR:
                continue
            permissions = self.bot.config["level_permissions"].get(level.name, [])
            for perm in permissions:
                perm = int(perm)
                if perm == -1:
                    key = self.bot.modmail_guild.default_role
                else:
                    key = self.bot.modmail_guild.get_member(perm)
                    if key is None:
                        key = self.bot.modmail_guild.get_role(perm)
                if key is not None:
                    logger.info("Granting %s access to Modmail category.", key.name)
                    overwrites[key] = discord.PermissionOverwrite(read_messages=True)

        category = await self.bot.modmail_guild.create_category(name="Modmail", overwrites=overwrites)

        await category.edit(position=0)

        log_channel = await self.bot.modmail_guild.create_text_channel(name="bot-logs", category=category)

        embed = discord.Embed(
            title="Friendly Reminder",
            description=f"You may use the `{self.bot.prefix}config set log_channel_id "
            "<channel-id>` command to set up a custom log channel, then you can delete this default "
            f"{log_channel.mention} log channel.",
            color=self.bot.main_color,
        )

        embed.add_field(
            name="Thanks for using our bot!",
            value="If you like what you see, consider giving the "
            "[repo a star](https://github.com/kyb3r/modmail) :star: and if you are "
            "feeling extra generous, buy us coffee on [Patreon](https://patreon.com/kyber) :heart:!",
        )

        embed.set_footer(text=f'Type "{self.bot.prefix}help" for a complete list of commands.')
        await log_channel.send(embed=embed)

        self.bot.config["main_category_id"] = category.id
        self.bot.config["log_channel_id"] = log_channel.id

        await self.bot.config.update()
        await ctx.send(
            "**Successfully set up server.**\n"
            "Consider setting permission levels to give access to roles "
            "or users the ability to use Modmail.\n\n"
            f"Type:\n- `{self.bot.prefix}permissions` and `{self.bot.prefix}permissions add` "
            "for more info on setting permissions.\n"
            f"- `{self.bot.prefix}config help` for a list of available customizations."
        )

        if not self.bot.config["command_permissions"] and not self.bot.config["level_permissions"]:
            await self.bot.update_perms(PermissionLevel.REGULAR, -1)
            for owner_id in self.bot.bot_owner_ids:
                await self.bot.update_perms(PermissionLevel.OWNER, owner_id)

    @commands.group(aliases=["snippets"], invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet(self, ctx, *, name: str.lower = None):
        """
        Create pre-defined messages for use in threads.

        When `{prefix}snippet` is used by itself, this will retrieve
        a list of snippets that are currently set. `{prefix}snippet-name` will show what the
        snippet point to.

        To create a snippet:
        - `{prefix}snippet add snippet-name A pre-defined text.`

        You can use your snippet in a thread channel
        with `{prefix}snippet-name`, the message "A pre-defined text."
        will be sent to the recipient.

        Currently, there is not a built-in anonymous snippet command; however, a workaround
        is available using `{prefix}alias`. Here is how:
        - `{prefix}alias add snippet-name anonreply A pre-defined anonymous text.`

        See also `{prefix}alias`.
        """

        if name is not None:
            snippet_name = self.bot._resolve_snippet(name)

            if snippet_name is None:
                embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
            else:
                val = self.bot.snippets[snippet_name]
                embed = discord.Embed(
                    title=f'Snippet - "{snippet_name}":', description=val, color=self.bot.main_color
                )
            return await ctx.send(embed=embed)

        if not self.bot.snippets:
            embed = discord.Embed(
                color=self.bot.error_color, description="You dont have any snippets at the moment."
            )
            embed.set_footer(text=f'Check "{self.bot.prefix}help snippet add" to add a snippet.')
            embed.set_author(name="Snippets", icon_url=ctx.guild.icon.url)
            return await ctx.send(embed=embed)

        embeds = []

        for i, names in enumerate(zip_longest(*(iter(sorted(self.bot.snippets)),) * 15)):
            description = format_description(i, names)
            embed = discord.Embed(color=self.bot.main_color, description=description)
            embed.set_author(name="Snippets", icon_url=ctx.guild.icon.url)
            embeds.append(embed)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @snippet.command(name="raw")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_raw(self, ctx, *, name: str.lower):
        """
        View the raw content of a snippet.
        """
        snippet_name = self.bot._resolve_snippet(name)
        if snippet_name is None:
            embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
        else:
            val = truncate(escape_code_block(self.bot.snippets[snippet_name]), 2048 - 7)
            embed = discord.Embed(
                title=f'Raw snippet - "{snippet_name}":',
                description=f"```\n{val}```",
                color=self.bot.main_color,
            )

        return await ctx.send(embed=embed)

    @snippet.command(name="add", aliases=["create", "make"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_add(self, ctx, name: str.lower, *, value: commands.clean_content):
        """
        Add a snippet.

        Simply to add a snippet, do: ```
        {prefix}snippet add hey hello there :)
        ```
        then when you type `{prefix}hey`, "hello there :)" will get sent to the recipient.

        To add a multi-word snippet name, use quotes: ```
        {prefix}snippet add "two word" this is a two word snippet.
        ```
        """
        if self.bot.get_command(name):
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"A command with the same name already exists: `{name}`.",
            )
            return await ctx.send(embed=embed)
        elif name in self.bot.snippets:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"Snippet `{name}` already exists.",
            )
            return await ctx.send(embed=embed)

        if name in self.bot.aliases:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description=f"An alias that shares the same name exists: `{name}`.",
            )
            return await ctx.send(embed=embed)

        if len(name) > 120:
            embed = discord.Embed(
                title="Error",
                color=self.bot.error_color,
                description="Snippet names cannot be longer than 120 characters.",
            )
            return await ctx.send(embed=embed)

        self.bot.snippets[name] = value
        await self.bot.config.update()

        embed = discord.Embed(
            title="Added snippet",
            color=self.bot.main_color,
            description="Successfully created snippet.",
        )
        return await ctx.send(embed=embed)

    def _fix_aliases(self, snippet_being_deleted: str) -> Tuple[List[str]]:
        """
        Remove references to the snippet being deleted from aliases.

        Direct aliases to snippets are deleted, and aliases having
        other steps are edited.

        A tuple of dictionaries are returned. The first dictionary
        contains a mapping of alias names which were deleted to their
        original value, and the second dictionary contains a mapping
        of alias names which were edited to their original value.
        """
        deleted = {}
        edited = {}

        # Using a copy since we might need to delete aliases
        for alias, val in self.bot.aliases.copy().items():
            values = parse_alias(val)

            save_aliases = []

            for val in values:
                view = StringView(val)
                linked_command = view.get_word().lower()
                message = view.read_rest()

                if linked_command == snippet_being_deleted:
                    continue

                is_valid_snippet = snippet_being_deleted in self.bot.snippets

                if not self.bot.get_command(linked_command) and not is_valid_snippet:
                    alias_command = self.bot.aliases[linked_command]
                    save_aliases.extend(normalize_alias(alias_command, message))
                else:
                    save_aliases.append(val)

            if not save_aliases:
                original_value = self.bot.aliases.pop(alias)
                deleted[alias] = original_value
            else:
                original_alias = self.bot.aliases[alias]
                new_alias = " && ".join(f'"{a}"' for a in save_aliases)

                if original_alias != new_alias:
                    self.bot.aliases[alias] = new_alias
                    edited[alias] = original_alias

        return deleted, edited

    @snippet.command(name="remove", aliases=["del", "delete"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_remove(self, ctx, *, name: str.lower):
        """Remove a snippet."""
        if name in self.bot.snippets:
            deleted_aliases, edited_aliases = self._fix_aliases(name)

            deleted_aliases_string = ",".join(f"`{alias}`" for alias in deleted_aliases)
            if len(deleted_aliases) == 1:
                deleted_aliases_output = f"The `{deleted_aliases_string}` direct alias has been removed."
            elif deleted_aliases:
                deleted_aliases_output = (
                    f"The following direct aliases have been removed: {deleted_aliases_string}."
                )
            else:
                deleted_aliases_output = None

            if len(edited_aliases) == 1:
                alias, val = edited_aliases.popitem()
                edited_aliases_output = (
                    f"Steps pointing to this snippet have been removed from the `{alias}` alias"
                    f" (previous value: `{val}`).`"
                )
            elif edited_aliases:
                alias_list = "\n".join(
                    [
                        f"- `{alias_name}` (previous value: `{val}`)"
                        for alias_name, val in edited_aliases.items()
                    ]
                )
                edited_aliases_output = (
                    f"Steps pointing to this snippet have been removed from the following aliases:"
                    f"\n\n{alias_list}"
                )
            else:
                edited_aliases_output = None

            description = f"Snippet `{name}` is now deleted."
            if deleted_aliases_output:
                description += f"\n\n{deleted_aliases_output}"
            if edited_aliases_output:
                description += f"\n\n{edited_aliases_output}"

            embed = discord.Embed(
                title="Removed snippet",
                color=self.bot.main_color,
                description=description,
            )
            self.bot.snippets.pop(name)
            await self.bot.config.update()
        else:
            embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
        await ctx.send(embed=embed)

    @snippet.command(name="edit")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_edit(self, ctx, name: str.lower, *, value):
        """
        Edit a snippet.

        To edit a multi-word snippet name, use quotes: ```
        {prefix}snippet edit "two word" this is a new two word snippet.
        ```
        """
        if name in self.bot.snippets:
            self.bot.snippets[name] = value
            await self.bot.config.update()

            embed = discord.Embed(
                title="Edited snippet",
                color=self.bot.main_color,
                description=f'`{name}` will now send "{value}".',
            )
        else:
            embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
        await ctx.send(embed=embed)

    @commands.command(usage="<category> [options]")
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @checks.thread_only()
    async def move(self, ctx, *, arguments):
        """
        Move a thread to another category.

        `category` may be a category ID, mention, or name.
        `options` is a string which takes in arguments on how to perform the move. Ex: "silently"
        """
        split_args = arguments.strip('"').split(" ")
        category = None

        # manually parse arguments, consumes as much of args as possible for category
        for i in range(len(split_args)):
            try:
                if i == 0:
                    fmt = arguments
                else:
                    fmt = " ".join(split_args[:-i])

                category = await SimilarCategoryConverter().convert(ctx, fmt)
            except commands.BadArgument:
                if i == len(split_args) - 1:
                    # last one
                    raise
                pass
            else:
                break

        if not category:
            raise commands.ChannelNotFound(arguments)

        options = " ".join(arguments.split(" ")[-i:])

        thread = ctx.thread
        silent = False

        if options:
            silent_words = ["silent", "silently"]
            silent = any(word in silent_words for word in options.split())

        await thread.channel.move(
            category=category, end=True, sync_permissions=True, reason=f"{ctx.author} moved this thread."
        )

        if self.bot.config["thread_move_notify"] and not silent:
            embed = discord.Embed(
                title=self.bot.config["thread_move_title"],
                description=self.bot.config["thread_move_response"],
                color=self.bot.main_color,
            )
            await thread.recipient.send(embed=embed)

        if self.bot.config["thread_move_notify_mods"]:
            mention = self.bot.config["mention"]
            if mention is not None:
                msg = f"{mention}, thread has been moved."
            else:
                msg = "Thread has been moved."
            await thread.channel.send(msg)

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    async def send_scheduled_close_message(self, ctx, after, silent=False):
        human_delta = human_timedelta(after.dt)

        silent = "*silently* " if silent else ""

        embed = discord.Embed(
            title="Scheduled close",
            description=f"This thread will close {silent}{human_delta}.",
            color=self.bot.error_color,
        )

        if after.arg and not silent:
            embed.add_field(name="Message", value=after.arg)

        embed.set_footer(text="Closing will be cancelled if a thread message is sent.")
        embed.timestamp = after.dt

        await ctx.send(embed=embed)

    @commands.command(usage="[after] [close message]")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def close(
        self,
        ctx,
        option: Optional[Literal["silent", "silently", "cancel"]] = "",
        *,
        after: UserFriendlyTime = None,
    ):
        """
        Close the current thread.
        Close after a period of time:
        - `{prefix}close in 5 hours`
        - `{prefix}close 2m30s`
        Custom close messages:
        - `{prefix}close 2 hours The issue has been resolved.`
        - `{prefix}close We will contact you once we find out more.`
        Silently close a thread (no message)
        - `{prefix}close silently`
        - `{prefix}close in 10m silently`
        Stop a thread from closing:
        - `{prefix}close cancel`
        """

        thread = ctx.thread

        close_after = (after.dt - after.now).total_seconds() if after else 0
        silent = any(x == option for x in {"silent", "silently"})
        cancel = option == "cancel"

        if cancel:
            if thread.close_task is not None or thread.auto_close_task is not None:
                await thread.cancel_closure(all=True)
                embed = discord.Embed(
                    color=self.bot.main_color, description="Scheduled close has been cancelled."
                )
            else:
                embed = discord.Embed(
                    color=self.bot.error_color,
                    description="This thread has not already been scheduled to close.",
                )

            return await ctx.send(embed=embed)

        message = after.arg if after else None
        if self.bot.config["require_close_reason"] and message is None:
            raise commands.BadArgument("Provide a reason for closing the thread.")

        if after and after.dt > after.now:
            await self.send_scheduled_close_message(ctx, after, silent)

        await thread.close(closer=ctx.author, after=close_after, message=message, silent=silent)

    @staticmethod
    def parse_user_or_role(ctx, user_or_role):
        mention = None
        if user_or_role is None:
            mention = ctx.author.mention
        elif hasattr(user_or_role, "mention"):
            mention = user_or_role.mention
        elif user_or_role in {"here", "everyone", "@here", "@everyone"}:
            mention = "@" + user_or_role.lstrip("@")
        return mention


    @commands.command(aliases=["alert"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def notify(self, ctx, *, user_or_role: Union[discord.Role, User, str.lower, None] = None):
        """
        Notify a user or role when the next thread message received.

        Once a thread message is received, `user_or_role` will be pinged once.

        Leave `user_or_role` empty to notify yourself.
        `@here` and `@everyone` can be substituted with `here` and `everyone`.
        `user_or_role` may be a user ID, mention, name. role ID, mention, name, "everyone", or "here".
        """
        mention = self.parse_user_or_role(ctx, user_or_role)
        if mention is None:
            raise commands.BadArgument(f"{user_or_role} is not a valid user or role.")

        thread = ctx.thread

        if str(thread.id) not in self.bot.config["notification_squad"]:
            self.bot.config["notification_squad"][str(thread.id)] = []

        mentions = self.bot.config["notification_squad"][str(thread.id)]

        if mention in mentions:
            embed = discord.Embed(
                color=self.bot.error_color,
                description=f"{mention} is already going to be mentioned.",
            )
        else:
            mentions.append(mention)
            await self.bot.config.update()
            embed = discord.Embed(
                color=self.bot.main_color,
                description=f"{mention} will be mentioned on the next message received.",
            )
        return await ctx.send(embed=embed)

    @commands.command(aliases=["unalert"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def unnotify(self, ctx, *, user_or_role: Union[discord.Role, User, str.lower, None] = None):
        """
        Un-notify a user, role, or yourself from a thread.

        Leave `user_or_role` empty to un-notify yourself.
        `@here` and `@everyone` can be substituted with `here` and `everyone`.
        `user_or_role` may be a user ID, mention, name, role ID, mention, name, "everyone", or "here".
        """
        mention = self.parse_user_or_role(ctx, user_or_role)
        if mention is None:
            mention = f"`{user_or_role}`"

        thread = ctx.thread

        if str(thread.id) not in self.bot.config["notification_squad"]:
            self.bot.config["notification_squad"][str(thread.id)] = []

        mentions = self.bot.config["notification_squad"][str(thread.id)]

        if mention not in mentions:
            embed = discord.Embed(
                color=self.bot.error_color,
                description=f"{mention} does not have a pending notification.",
            )
        else:
            mentions.remove(mention)
            await self.bot.config.update()
            embed = discord.Embed(
                color=self.bot.main_color, description=f"{mention} will no longer be notified."
            )
        return await ctx.send(embed=embed)

    @commands.command(aliases=["sub"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def subscribe(self, ctx, *, user_or_role: Union[discord.Role, User, str.lower, None] = None):
        """
        Notify a user, role, or yourself for every thread message received.

        You will be pinged for every thread message received until you unsubscribe.

        Leave `user_or_role` empty to subscribe yourself.
        `@here` and `@everyone` can be substituted with `here` and `everyone`.
        `user_or_role` may be a user ID, mention, name, role ID, mention, name, "everyone", or "here".
        """
        mention = self.parse_user_or_role(ctx, user_or_role)
        if mention is None:
            raise commands.BadArgument(f"{user_or_role} is not a valid user or role.")

        thread = ctx.thread

        if str(thread.id) not in self.bot.config["subscriptions"]:
            self.bot.config["subscriptions"][str(thread.id)] = []

        mentions = self.bot.config["subscriptions"][str(thread.id)]

        if mention in mentions:
            embed = discord.Embed(
                color=self.bot.error_color,
                description=f"{mention} is already subscribed to this thread.",
            )
        else:
            mentions.append(mention)
            await self.bot.config.update()
            embed = discord.Embed(
                color=self.bot.main_color,
                description=f"{mention} will now be notified of all messages received.",
            )
        return await ctx.send(embed=embed)

    @commands.command(aliases=["unsub"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def unsubscribe(self, ctx, *, user_or_role: Union[discord.Role, User, str.lower, None] = None):
        """
        Unsubscribe a user, role, or yourself from a thread.

        Leave `user_or_role` empty to unsubscribe yourself.
        `@here` and `@everyone` can be substituted with `here` and `everyone`.
        `user_or_role` may be a user ID, mention, name, role ID, mention, name, "everyone", or "here".
        """
        mention = self.parse_user_or_role(ctx, user_or_role)
        if mention is None:
            mention = f"`{user_or_role}`"

        thread = ctx.thread

        if str(thread.id) not in self.bot.config["subscriptions"]:
            self.bot.config["subscriptions"][str(thread.id)] = []

        mentions = self.bot.config["subscriptions"][str(thread.id)]

        if mention not in mentions:
            embed = discord.Embed(
                color=self.bot.error_color,
                description=f"{mention} is not subscribed to this thread.",
            )
        else:
            mentions.remove(mention)
            await self.bot.config.update()
            embed = discord.Embed(
                color=self.bot.main_color,
                description=f"{mention} is now unsubscribed from this thread.",
            )
        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def nsfw(self, ctx):
        """Flags a Modmail thread as NSFW (not safe for work)."""
        await ctx.channel.edit(nsfw=True)
        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def sfw(self, ctx):
        """Flags a Modmail thread as SFW (safe for work)."""
        await ctx.channel.edit(nsfw=False)
        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def msglink(self, ctx, message_id: int):
        """Retrieves the link to a message in the current thread."""
        try:
            message = await ctx.thread.recipient.fetch_message(message_id)
        except discord.NotFound:
            embed = discord.Embed(
                color=self.bot.error_color, description="Message not found or no longer exists."
            )
        else:
            embed = discord.Embed(color=self.bot.main_color, description=message.jump_url)
        await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def loglink(self, ctx):
        """Retrieves the link to the current thread's logs."""
        log_link = await self.bot.api.get_log_link(ctx.channel.id)
        await ctx.send(embed=discord.Embed(color=self.bot.main_color, description=log_link))

    def format_log_embeds(self, logs, avatar_url):
        embeds = []
        logs = tuple(logs)
        title = f"Total Results Found ({len(logs)})"

        for entry in logs:
            created_at = parser.parse(entry["created_at"]).astimezone(timezone.utc)

            prefix = self.bot.config["log_url_prefix"].strip("/")
            if prefix == "NONE":
                prefix = ""
            log_url = (
                f"{self.bot.config['log_url'].strip('/')}{'/' + prefix if prefix else ''}/{entry['key']}"
            )

            username = entry["recipient"]["name"] + "#"
            username += entry["recipient"]["discriminator"]

            embed = discord.Embed(color=self.bot.main_color, timestamp=created_at)
            embed.set_author(name=f"{title} - {username}", icon_url=avatar_url.url, url=log_url)
            embed.url = log_url
            embed.add_field(name="Created", value=human_timedelta(created_at))
            closer = entry.get("closer")
            if closer is None:
                closer_msg = "Unknown"
            else:
                closer_msg = f"<@{closer['id']}>"
            embed.add_field(name="Closed By", value=closer_msg)

            if entry["recipient"]["id"] != entry["creator"]["id"]:
                embed.add_field(name="Created by", value=f"<@{entry['creator']['id']}>")

            if entry["title"]:
                embed.add_field(name="Title", value=entry["title"], inline=False)

            embed.add_field(name="Preview", value=format_preview(entry["messages"]), inline=False)

            if closer is not None:
                # BUG: Currently, logviewer can't display logs without a closer.
                embed.add_field(name="Link", value=log_url)
            else:
                logger.debug("Invalid log entry: no closer.")
                embed.add_field(name="Log Key", value=f"`{entry['key']}`")

            embed.set_footer(text="Recipient ID: " + str(entry["recipient"]["id"]))
            embeds.append(embed)
        return embeds

    @commands.command(cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 600, BucketType.channel)
    async def title(self, ctx, *, name: str):
        """Sets title for a thread"""
        await ctx.thread.set_title(name)
        sent_emoji, _ = await self.bot.retrieve_emoji()
        await ctx.message.pin()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 600, BucketType.channel)
    async def adduser(self, ctx, *users_arg: Union[discord.Member, discord.Role, str]):
        """Adds a user to a modmail thread

        `options` can be `silent` or `silently`.
        """
        silent = False
        users = []
        for u in users_arg:
            if isinstance(u, str):
                if "silent" in u or "silently" in u:
                    silent = True
            elif isinstance(u, discord.Role):
                users += u.members
            elif isinstance(u, discord.Member):
                users.append(u)

        for u in users:
            # u is a discord.Member
            curr_thread = await self.bot.threads.find(recipient=u)
            if curr_thread == ctx.thread:
                users.remove(u)
                continue

            if curr_thread:
                em = discord.Embed(
                    title="Error",
                    description=f"{u.mention} is already in a thread: {curr_thread.channel.mention}.",
                    color=self.bot.error_color,
                )
                await ctx.send(embed=em)
                ctx.command.reset_cooldown(ctx)
                return

        if not users:
            em = discord.Embed(
                title="Error",
                description="All users are already in the thread.",
                color=self.bot.error_color,
            )
            await ctx.send(embed=em)
            ctx.command.reset_cooldown(ctx)
            return

        if len(users + ctx.thread.recipients) > 5:
            em = discord.Embed(
                title="Error",
                description="Only 5 users are allowed in a group conversation",
                color=self.bot.error_color,
            )
            await ctx.send(embed=em)
            ctx.command.reset_cooldown(ctx)
            return

        to_exec = []
        if not silent:
            description = self.bot.formatter.format(
                self.bot.config["private_added_to_group_response"], moderator=ctx.author
            )
            em = discord.Embed(
                title=self.bot.config["private_added_to_group_title"],
                description=description,
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()
            em.set_footer(text=str(ctx.author), icon_url=ctx.author.display_avatar.url)
            for u in users:
                to_exec.append(u.send(embed=em))

            description = self.bot.formatter.format(
                self.bot.config["public_added_to_group_response"],
                moderator=ctx.author,
                users=", ".join(u.name for u in users),
            )
            em = discord.Embed(
                title=self.bot.config["public_added_to_group_title"],
                description=description,
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].display_avatar.url)

            for i in ctx.thread.recipients:
                if i not in users:
                    to_exec.append(i.send(embed=em))

        await ctx.thread.add_users(users)
        if to_exec:
            await asyncio.gather(*to_exec)

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 600, BucketType.channel)
    async def removeuser(self, ctx, *users_arg: Union[discord.Member, discord.Role, str]):
        """Removes a user from a modmail thread

        `options` can be `silent` or `silently`.
        """
        silent = False
        users = []
        for u in users_arg:
            if isinstance(u, str):
                if "silent" in u or "silently" in u:
                    silent = True
            elif isinstance(u, discord.Role):
                users += u.members
            elif isinstance(u, discord.Member):
                users.append(u)

        for u in users:
            # u is a discord.Member
            curr_thread = await self.bot.threads.find(recipient=u)
            if ctx.thread != curr_thread:
                em = discord.Embed(
                    title="Error",
                    description=f"{u.mention} is not in this thread.",
                    color=self.bot.error_color,
                )
                await ctx.send(embed=em)
                ctx.command.reset_cooldown(ctx)
                return
            elif ctx.thread.recipient == u:
                em = discord.Embed(
                    title="Error",
                    description=f"{u.mention} is the main recipient of the thread and cannot be removed.",
                    color=self.bot.error_color,
                )
                await ctx.send(embed=em)
                ctx.command.reset_cooldown(ctx)
                return

        if not users:
            em = discord.Embed(
                title="Error",
                description="No valid users to remove.",
                color=self.bot.error_color,
            )
            await ctx.send(embed=em)
            ctx.command.reset_cooldown(ctx)
            return

        to_exec = []
        if not silent:
            description = self.bot.formatter.format(
                self.bot.config["private_removed_from_group_response"], moderator=ctx.author
            )
            em = discord.Embed(
                title=self.bot.config["private_removed_from_group_title"],
                description=description,
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()
            em.set_footer(text=str(ctx.author), icon_url=ctx.author.display_avatar.url)
            for u in users:
                to_exec.append(u.send(embed=em))

            description = self.bot.formatter.format(
                self.bot.config["public_removed_from_group_response"],
                moderator=ctx.author,
                users=", ".join(u.name for u in users),
            )
            em = discord.Embed(
                title=self.bot.config["public_removed_from_group_title"],
                description=description,
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].display_avatar.url)

            for i in ctx.thread.recipients:
                if i not in users:
                    to_exec.append(i.send(embed=em))

        await ctx.thread.remove_users(users)
        if to_exec:
            await asyncio.gather(*to_exec)

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 600, BucketType.channel)
    async def anonadduser(self, ctx, *users_arg: Union[discord.Member, discord.Role, str]):
        """Adds a user to a modmail thread anonymously

        `options` can be `silent` or `silently`.
        """
        silent = False
        users = []
        for u in users_arg:
            if isinstance(u, str):
                if "silent" in u or "silently" in u:
                    silent = True
            elif isinstance(u, discord.Role):
                users += u.members
            elif isinstance(u, discord.Member):
                users.append(u)

        for u in users:
            curr_thread = await self.bot.threads.find(recipient=u)
            if curr_thread == ctx.thread:
                users.remove(u)
                continue

            if curr_thread:
                em = discord.Embed(
                    title="Error",
                    description=f"{u.mention} is already in a thread: {curr_thread.channel.mention}.",
                    color=self.bot.error_color,
                )
                await ctx.send(embed=em)
                ctx.command.reset_cooldown(ctx)
                return

        if not users:
            em = discord.Embed(
                title="Error",
                description="All users are already in the thread.",
                color=self.bot.error_color,
            )
            await ctx.send(embed=em)
            ctx.command.reset_cooldown(ctx)
            return

        to_exec = []
        if not silent:
            em = discord.Embed(
                title=self.bot.config["private_added_to_group_title"],
                description=self.bot.config["private_added_to_group_description_anon"],
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()

            tag = self.bot.config["mod_tag"]
            if tag is None:
                tag = str(get_top_role(ctx.author, self.bot.config["use_hoisted_top_role"]))
            name = self.bot.config["anon_username"]
            if name is None:
                name = tag
            avatar_url = self.bot.config["anon_avatar_url"]
            if avatar_url is None:
                avatar_url = self.bot.guild.icon.url
            em.set_footer(text=name, icon_url=avatar_url.url)

            for u in users:
                to_exec.append(u.send(embed=em))

            description = self.bot.formatter.format(
                self.bot.config["public_added_to_group_description_anon"],
                users=", ".join(u.name for u in users),
            )
            em = discord.Embed(
                title=self.bot.config["public_added_to_group_title"],
                description=description,
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].display_avatar.url)

            for i in ctx.thread.recipients:
                if i not in users:
                    to_exec.append(i.send(embed=em))

        await ctx.thread.add_users(users)
        if to_exec:
            await asyncio.gather(*to_exec)

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 600, BucketType.channel)
    async def anonremoveuser(self, ctx, *users_arg: Union[discord.Member, discord.Role, str]):
        """Removes a user from a modmail thread anonymously

        `options` can be `silent` or `silently`.
        """
        silent = False
        users = []
        for u in users_arg:
            if isinstance(u, str):
                if "silent" in u or "silently" in u:
                    silent = True
            elif isinstance(u, discord.Role):
                users += u.members
            elif isinstance(u, discord.Member):
                users.append(u)

        for u in users:
            curr_thread = await self.bot.threads.find(recipient=u)
            if ctx.thread != curr_thread:
                em = discord.Embed(
                    title="Error",
                    description=f"{u.mention} is not in this thread.",
                    color=self.bot.error_color,
                )
                await ctx.send(embed=em)
                ctx.command.reset_cooldown(ctx)
                return
            elif ctx.thread.recipient == u:
                em = discord.Embed(
                    title="Error",
                    description=f"{u.mention} is the main recipient of the thread and cannot be removed.",
                    color=self.bot.error_color,
                )
                await ctx.send(embed=em)
                ctx.command.reset_cooldown(ctx)
                return

        to_exec = []
        if not silent:
            em = discord.Embed(
                title=self.bot.config["private_removed_from_group_title"],
                description=self.bot.config["private_removed_from_group_description_anon"],
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()

            tag = self.bot.config["mod_tag"]
            if tag is None:
                tag = str(get_top_role(ctx.author, self.bot.config["use_hoisted_top_role"]))
            name = self.bot.config["anon_username"]
            if name is None:
                name = tag
            avatar_url = self.bot.config["anon_avatar_url"]
            if avatar_url is None:
                avatar_url = self.bot.guild.icon.url
            em.set_footer(text=name, icon_url=avatar_url.url)

            for u in users:
                to_exec.append(u.send(embed=em))

            description = self.bot.formatter.format(
                self.bot.config["public_removed_from_group_description_anon"],
                users=", ".join(u.name for u in users),
            )
            em = discord.Embed(
                title=self.bot.config["public_removed_from_group_title"],
                description=description,
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].display_avatar.url)

            for i in ctx.thread.recipients:
                if i not in users:
                    to_exec.append(i.send(embed=em))

        await ctx.thread.remove_users(users)
        if to_exec:
            await asyncio.gather(*to_exec)

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def logs(self, ctx, *, user: User = None):
        """
        Get previous Modmail thread logs of a member.

        Leave `user` blank when this command is used within a
        thread channel to show logs for the current recipient.
        `user` may be a user ID, mention, or name.
        """

        await ctx.typing()

        if not user:
            thread = ctx.thread
            if not thread:
                raise commands.MissingRequiredArgument(SimpleNamespace(name="member"))
            user = thread.recipient or await self.bot.get_or_fetch_user(thread.id)

        default_avatar = "https://cdn.discordapp.com/embed/avatars/0.png"
        icon_url = getattr(user, "avatar_url", default_avatar)

        logs = await self.bot.api.get_user_logs(user.id)

        if not any(not log["open"] for log in logs):
            embed = discord.Embed(
                color=self.bot.error_color,
                description="This user does not have any previous logs.",
            )
            return await ctx.send(embed=embed)

        logs = reversed([log for log in logs if not log["open"]])

        embeds = self.format_log_embeds(logs, avatar_url=icon_url)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @logs.command(name="closed-by", aliases=["closeby"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def logs_closed_by(self, ctx, *, user: User = None):
        """
        Get all logs closed by the specified user.

        If no `user` is provided, the user will be the person who sent this command.
        `user` may be a user ID, mention, or name.
        """
        user = user if user is not None else ctx.author

        entries = await self.bot.api.search_closed_by(user.id)
        embeds = self.format_log_embeds(entries, avatar_url=self.bot.guild.icon.url)

        if not embeds:
            embed = discord.Embed(
                color=self.bot.error_color,
                description="No log entries have been found for that query.",
            )
            return await ctx.send(embed=embed)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @logs.command(name="delete", aliases=["wipe"])
    @checks.has_permissions(PermissionLevel.OWNER)
    async def logs_delete(self, ctx, key_or_link: str):
        """
        Wipe a log entry from the database.
        """
        key = key_or_link.split("/")[-1]

        success = await self.bot.api.delete_log_entry(key)

        if not success:
            embed = discord.Embed(
                title="Error",
                description=f"Log entry `{key}` not found.",
                color=self.bot.error_color,
            )
        else:
            embed = discord.Embed(
                title="Success",
                description=f"Log entry `{key}` successfully deleted.",
                color=self.bot.main_color,
            )

        await ctx.send(embed=embed)

    @logs.command(name="responded")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def logs_responded(self, ctx, *, user: User = None):
        """
        Get all logs where the specified user has responded at least once.

        If no `user` is provided, the user will be the person who sent this command.
        `user` may be a user ID, mention, or name.
        """
        user = user if user is not None else ctx.author

        entries = await self.bot.api.get_responded_logs(user.id)

        embeds = self.format_log_embeds(entries, avatar_url=self.bot.guild.icon.url)

        if not embeds:
            embed = discord.Embed(
                color=self.bot.error_color,
                description=f"{getattr(user, 'mention', user.id)} has not responded to any threads.",
            )
            return await ctx.send(embed=embed)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @logs.command(name="search", aliases=["find"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def logs_search(self, ctx, limit: Optional[int] = None, *, query):
        """
        Retrieve all logs that contain messages with your query.

        Provide a `limit` to specify the maximum number of logs the bot should find.
        """

        await ctx.typing()

        entries = await self.bot.api.search_by_text(query, limit)

        embeds = self.format_log_embeds(entries, avatar_url=self.bot.guild.icon.url)

        if not embeds:
            embed = discord.Embed(
                color=self.bot.error_color,
                description="No log entries have been found for that query.",
            )
            return await ctx.send(embed=embed)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def reply(self, ctx, *, msg: str = ""):
        """
        Reply to a Modmail thread.

        Supports attachments and images as well as
        automatically embedding image URLs.
        """

        ctx.message.content = msg

        async with ctx.typing():
            await ctx.thread.reply(ctx.message)

    @commands.command(aliases=["formatreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def freply(self, ctx, *, msg: str = ""):
        """
        Reply to a Modmail thread with variables.

        Works just like `{prefix}reply`, however with the addition of three variables:
          - `{{channel}}` - the `discord.TextChannel` object
          - `{{recipient}}` - the `discord.User` object of the recipient
          - `{{author}}` - the `discord.User` object of the author

        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        msg = self.bot.formatter.format(
            msg, channel=ctx.channel, recipient=ctx.thread.recipient, author=ctx.message.author
        )
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message)

    @commands.command(aliases=["formatanonreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def fareply(self, ctx, *, msg: str = ""):
        """
        Anonymously reply to a Modmail thread with variables.

        Works just like `{prefix}areply`, however with the addition of three variables:
          - `{{channel}}` - the `discord.TextChannel` object
          - `{{recipient}}` - the `discord.User` object of the recipient
          - `{{author}}` - the `discord.User` object of the author

        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        msg = self.bot.formatter.format(
            msg, channel=ctx.channel, recipient=ctx.thread.recipient, author=ctx.message.author
        )
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, anonymous=True)

    @commands.command(aliases=["formatplainreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def fpreply(self, ctx, *, msg: str = ""):
        """
        Reply to a Modmail thread with variables and a plain message.

        Works just like `{prefix}areply`, however with the addition of three variables:
          - `{{channel}}` - the `discord.TextChannel` object
          - `{{recipient}}` - the `discord.User` object of the recipient
          - `{{author}}` - the `discord.User` object of the author

        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        msg = self.bot.formatter.format(
            msg, channel=ctx.channel, recipient=ctx.thread.recipient, author=ctx.message.author
        )
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, plain=True)

    @commands.command(aliases=["formatplainanonreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def fpareply(self, ctx, *, msg: str = ""):
        """
        Anonymously reply to a Modmail thread with variables and a plain message.

        Works just like `{prefix}areply`, however with the addition of three variables:
          - `{{channel}}` - the `discord.TextChannel` object
          - `{{recipient}}` - the `discord.User` object of the recipient
          - `{{author}}` - the `discord.User` object of the author

        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        msg = self.bot.formatter.format(
            msg, channel=ctx.channel, recipient=ctx.thread.recipient, author=ctx.message.author
        )
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, anonymous=True, plain=True)

    @commands.command(aliases=["anonreply", "anonymousreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def areply(self, ctx, *, msg: str = ""):
        """
        Reply to a thread anonymously.

        You can edit the anonymous user's name,
        avatar and tag using the config command.

        Edit the `anon_username`, `anon_avatar_url`
        and `anon_tag` config variables to do so.
        """
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, anonymous=True)

    @commands.command(aliases=["plainreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def preply(self, ctx, *, msg: str = ""):
        """
        Reply to a Modmail thread with a plain message.

        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, plain=True)

    @commands.command(aliases=["plainanonreply", "plainanonymousreply"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def pareply(self, ctx, *, msg: str = ""):
        """
        Reply to a Modmail thread with a plain message and anonymously.

        Supports attachments and images as well as
        automatically embedding image URLs.
        """
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, anonymous=True, plain=True)

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def note(self, ctx, *, msg: str = ""):
        """
        Take a note about the current thread.

        Useful for noting context.
        """
        ctx.message.content = msg
        async with ctx.typing():
            msg = await ctx.thread.note(ctx.message)
            await msg.pin()

    @note.command(name="persistent", aliases=["persist"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def note_persistent(self, ctx, *, msg: str = ""):
        """
        Take a persistent note about the current user.
        """
        ctx.message.content = msg
        async with ctx.typing():
            msg = await ctx.thread.note(ctx.message, persistent=True)
            await msg.pin()
        await self.bot.api.create_note(recipient=ctx.thread.recipient, message=ctx.message, message_id=msg.id)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def edit(self, ctx, message_id: Optional[int] = None, *, message: str):
        """
        Edit a message that was sent using the reply or anonreply command.

        If no `message_id` is provided,
        the last message sent by a staff will be edited.

        Note: attachments **cannot** be edited.
        """
        thread = ctx.thread

        try:
            await thread.edit_message(message_id, message)
        except ValueError:
            return await ctx.send(
                embed=discord.Embed(
                    title="Failed",
                    description="Cannot find a message to edit.",
                    color=self.bot.error_color,
                )
            )

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    async def selfcontact(self, ctx):
        """Creates a thread with yourself"""
        await ctx.invoke(self.contact, users=[ctx.author])

    @commands.command(usage="<user> [category] [options]")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def contact(
        self,
        ctx,
        users: commands.Greedy[
            Union[Literal["silent", "silently"], discord.Member, discord.User, discord.Role]
        ],
        *,
        category: SimilarCategoryConverter = None,
        manual_trigger=True,
    ):
        """
        Create a thread with a specified member.

        If `category` is specified, the thread
        will be created in that specified category.

        `category`, if specified, may be a category ID, mention, or name.
        `users` may be a user ID, mention, or name. If multiple users are specified, a group thread will start.
        A maximum of 5 users are allowed.
        `options` can be `silent` or `silently`.
        """
        silent = any(x in users for x in ("silent", "silently"))
        if silent:
            try:
                users.remove("silent")
            except ValueError:
                pass

            try:
                users.remove("silently")
            except ValueError:
                pass

        if isinstance(category, str):
            category = category.split()

            category = " ".join(category)
            if category:
                try:
                    category = await SimilarCategoryConverter().convert(
                        ctx, category
                    )  # attempt to find a category again
                except commands.BadArgument:
                    category = None

            if isinstance(category, str):
                category = None

        errors = []
        for u in list(users):
            if isinstance(u, discord.Role):
                users += u.members
                users.remove(u)

        for u in list(users):
            exists = await self.bot.threads.find(recipient=u)
            if exists:
                errors.append(f"A thread for {u} already exists.")
                if exists.channel:
                    errors[-1] += f" in {exists.channel.mention}"
                errors[-1] += "."
                users.remove(u)
            elif u.bot:
                errors.append(f"{u} is a bot, cannot add to thread.")
                users.remove(u)
            elif await self.bot.is_blocked(u):
                ref = f"{u.mention} is" if ctx.author != u else "You are"
                errors.append(f"{ref} currently blocked from contacting {self.bot.user.name}.")
                users.remove(u)

        if len(users) > 5:
            errors.append("Group conversations only support 5 users.")
            users = []

        if errors or not users:
            if not users:
                # no users left
                title = "Thread not created"
            else:
                title = None

            if manual_trigger:  # not react to contact
                embed = discord.Embed(title=title, color=self.bot.error_color, description="\n".join(errors))
                await ctx.send(embed=embed, delete_after=10)

            if not users:
                # end
                return

        creator = ctx.author if manual_trigger else users[0]

        thread = await self.bot.threads.create(
            recipient=users[0],
            creator=creator,
            category=category,
            manual_trigger=manual_trigger,
        )

        if thread.cancelled:
            return

        if self.bot.config["dm_disabled"] in (DMDisabled.NEW_THREADS, DMDisabled.ALL_THREADS):
            logger.info("Contacting user %s when Modmail DM is disabled.", users[0])

        if not silent and not self.bot.config.get("thread_contact_silently"):
            if creator.id == users[0].id:
                description = self.bot.config["thread_creation_self_contact_response"]
            else:
                description = self.bot.formatter.format(
                    self.bot.config["thread_creation_contact_response"], creator=creator
                )

            em = discord.Embed(
                title=self.bot.config["thread_creation_contact_title"],
                description=description,
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = discord.utils.utcnow()
            em.set_footer(text=f"{creator}", icon_url=creator.display_avatar.url)

            for u in users:
                await u.send(embed=em)

        embed = discord.Embed(
            title="Created Thread",
            description=f"Thread started by {creator.mention} for {', '.join(u.mention for u in users)}.",
            color=self.bot.main_color,
        )
        await thread.wait_until_ready()

        if users[1:]:
            await thread.add_users(users[1:])

        await thread.channel.send(embed=embed)

        if manual_trigger:
            sent_emoji, _ = await self.bot.retrieve_emoji()
            await self.bot.add_reaction(ctx.message, sent_emoji)
            await asyncio.sleep(5)
            await ctx.message.delete()

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @trigger_typing
    async def blocked(self, ctx):
        """Retrieve a list of blocked users."""

        roles = []
        users = []
        now = ctx.message.created_at

        blocked_users = list(self.bot.blocked_users.items())
        for id_, reason in blocked_users:
            # parse "reason" and check if block is expired
            try:
                end_time, after = extract_block_timestamp(reason, id_)
            except ValueError:
                continue

            if end_time is not None:
                if after <= 0:
                    # No longer blocked
                    self.bot.blocked_users.pop(str(id_))
                    logger.debug("No longer blocked, user %s.", id_)
                    continue

            try:
                user = await self.bot.get_or_fetch_user(int(id_))
            except discord.NotFound:
                users.append((id_, reason))
            else:
                users.append((user.mention, reason))

        blocked_roles = list(self.bot.blocked_roles.items())
        for id_, reason in blocked_roles:
            # parse "reason" and check if block is expired
            # etc "blah blah blah... until 2019-10-14T21:12:45.559948."
            try:
                end_time, after = extract_block_timestamp(reason, id_)
            except ValueError:
                continue

            if end_time is not None:
                if after <= 0:
                    # No longer blocked
                    self.bot.blocked_roles.pop(str(id_))
                    logger.debug("No longer blocked, role %s.", id_)
                    continue

            role = self.bot.guild.get_role(int(id_))
            if role:
                roles.append((role.mention, reason))

        user_embeds = [discord.Embed(title="Blocked Users", color=self.bot.main_color, description="")]

        if users:
            embed = user_embeds[0]

            for mention, reason in users:
                line = mention + f" - {reason or 'No Reason Provided'}\n"
                if len(embed.description) + len(line) > 2048:
                    embed = discord.Embed(
                        title="Blocked Users",
                        color=self.bot.main_color,
                        description=line,
                    )
                    user_embeds.append(embed)
                else:
                    embed.description += line
        else:
            user_embeds[0].description = "Currently there are no blocked users."

        if len(user_embeds) > 1:
            for n, em in enumerate(user_embeds):
                em.title = f"{em.title} [{n + 1}]"

        role_embeds = [discord.Embed(title="Blocked Roles", color=self.bot.main_color, description="")]

        if roles:
            embed = role_embeds[-1]

            for mention, reason in roles:
                line = mention + f" - {reason or 'No Reason Provided'}\n"
                if len(embed.description) + len(line) > 2048:
                    role_embeds[-1].set_author()
                    embed = discord.Embed(
                        title="Blocked Roles",
                        color=self.bot.main_color,
                        description=line,
                    )
                    role_embeds.append(embed)
                else:
                    embed.description += line
        else:
            role_embeds[-1].description = "Currently there are no blocked roles."

        if len(role_embeds) > 1:
            for n, em in enumerate(role_embeds):
                em.title = f"{em.title} [{n + 1}]"

        session = EmbedPaginatorSession(ctx, *user_embeds, *role_embeds)

        await session.run()

    @blocked.command(name="whitelist")
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @trigger_typing
    async def blocked_whitelist(self, ctx, *, user: User = None):
        """
        Whitelist or un-whitelist a user from getting blocked.

        Useful for preventing users from getting blocked by account_age/guild_age restrictions.
        """
        if user is None:
            thread = ctx.thread
            if thread:
                user = thread.recipient
            else:
                return await ctx.send_help(ctx.command)

        mention = getattr(user, "mention", f"`{user.id}`")
        msg = ""

        if str(user.id) in self.bot.blocked_whitelisted_users:
            embed = discord.Embed(
                title="Success",
                description=f"{mention} is no longer whitelisted.",
                color=self.bot.main_color,
            )
            self.bot.blocked_whitelisted_users.remove(str(user.id))
            return await ctx.send(embed=embed)

        self.bot.blocked_whitelisted_users.append(str(user.id))

        if str(user.id) in self.bot.blocked_users:
            msg = self.bot.blocked_users.get(str(user.id)) or ""
            self.bot.blocked_users.pop(str(user.id))

        await self.bot.config.update()

        if msg.startswith("System Message: "):
            # If the user is blocked internally (for example: below minimum account age)
            # Show an extended message stating the original internal message
            reason = msg[16:].strip().rstrip(".")
            embed = discord.Embed(
                title="Success",
                description=f"{mention} was previously blocked internally for "
                f'"{reason}". {mention} is now whitelisted.',
                color=self.bot.main_color,
            )
        else:
            embed = discord.Embed(
                title="Success",
                color=self.bot.main_color,
                description=f"{mention} is now whitelisted.",
            )

        return await ctx.send(embed=embed)

    @commands.command(usage="[user] [duration] [reason]")
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @trigger_typing
    async def block(
        self,
        ctx,
        user_or_role: Optional[Union[User, discord.Role]] = None,
        *,
        after: UserFriendlyTime = None,
    ):
        """
        Block a user or role from using Modmail.

        You may choose to set a time as to when the user will automatically be unblocked.

        Leave `user` blank when this command is used within a
        thread channel to block the current recipient.
        `user` may be a user ID, mention, or name.
        `duration` may be a simple "human-readable" time text. See `{prefix}help close` for examples.
        """

        if user_or_role is None:
            thread = ctx.thread
            if thread:
                user_or_role = thread.recipient
            elif after is None:
                raise commands.MissingRequiredArgument(SimpleNamespace(name="user or role"))
            else:
                raise commands.BadArgument(f'User or role "{after.arg}" not found.')

        mention = getattr(user_or_role, "mention", f"`{user_or_role.id}`")

        if (
            not isinstance(user_or_role, discord.Role)
            and str(user_or_role.id) in self.bot.blocked_whitelisted_users
        ):
            embed = discord.Embed(
                title="Error",
                description=f"Cannot block {mention}, user is whitelisted.",
                color=self.bot.error_color,
            )
            return await ctx.send(embed=embed)

        reason = f"by {escape_markdown(ctx.author.name)}#{ctx.author.discriminator}"

        if after is not None:
            if "%" in reason:
                raise commands.BadArgument('The reason contains illegal character "%".')

            if after.arg:
                fmt_dt = discord.utils.format_dt(after.dt, "R")
            if after.dt > after.now:
                fmt_dt = discord.utils.format_dt(after.dt, "f")

            reason += f" until {fmt_dt}"

        reason += "."

        if isinstance(user_or_role, discord.Role):
            msg = self.bot.blocked_roles.get(str(user_or_role.id))
        else:
            msg = self.bot.blocked_users.get(str(user_or_role.id))

        if msg is None:
            msg = ""

        if msg:
            old_reason = msg.strip().rstrip(".")
            embed = discord.Embed(
                title="Success",
                description=f"{mention} was previously blocked {old_reason}.\n"
                f"{mention} is now blocked {reason}",
                color=self.bot.main_color,
            )
        else:
            embed = discord.Embed(
                title="Success",
                color=self.bot.main_color,
                description=f"{mention} is now blocked {reason}",
            )

        if isinstance(user_or_role, discord.Role):
            self.bot.blocked_roles[str(user_or_role.id)] = reason
        else:
            self.bot.blocked_users[str(user_or_role.id)] = reason
        await self.bot.config.update()

        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @trigger_typing
    async def unblock(self, ctx, *, user_or_role: Union[User, Role] = None):
        """
        Unblock a user from using Modmail.

        Leave `user` blank when this command is used within a
        thread channel to unblock the current recipient.
        `user` may be a user ID, mention, or name.
        """

        if user_or_role is None:
            thread = ctx.thread
            if thread:
                user_or_role = thread.recipient
            else:
                raise commands.MissingRequiredArgument(SimpleNamespace(name="user"))

        mention = getattr(user_or_role, "mention", f"`{user_or_role.id}`")
        name = getattr(user_or_role, "name", f"`{user_or_role.id}`")

        if not isinstance(user_or_role, discord.Role) and str(user_or_role.id) in self.bot.blocked_users:
            msg = self.bot.blocked_users.pop(str(user_or_role.id)) or ""
            await self.bot.config.update()

            if msg.startswith("System Message: "):
                # If the user is blocked internally (for example: below minimum account age)
                # Show an extended message stating the original internal message
                reason = msg[16:].strip().rstrip(".") or "no reason"
                embed = discord.Embed(
                    title="Success",
                    description=f"{mention} was previously blocked internally {reason}.\n"
                    f"{mention} is no longer blocked.",
                    color=self.bot.main_color,
                )
                embed.set_footer(
                    text="However, if the original system block reason still applies, "
                    f"{name} will be automatically blocked again. "
                    f'Use "{self.bot.prefix}blocked whitelist {user_or_role.id}" to whitelist the user.'
                )
            else:
                embed = discord.Embed(
                    title="Success",
                    color=self.bot.main_color,
                    description=f"{mention} is no longer blocked.",
                )
        elif isinstance(user_or_role, discord.Role) and str(user_or_role.id) in self.bot.blocked_roles:
            msg = self.bot.blocked_roles.pop(str(user_or_role.id)) or ""
            await self.bot.config.update()

            embed = discord.Embed(
                title="Success",
                color=self.bot.main_color,
                description=f"{mention} is no longer blocked.",
            )
        else:
            embed = discord.Embed(
                title="Error", description=f"{mention} is not blocked.", color=self.bot.error_color
            )

        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def delete(self, ctx, message_id: int = None):
        """
        Delete a message that was sent using the reply command or a note.

        Deletes the previous message, unless a message ID is provided,
        which in that case, deletes the message with that message ID.

        Notes can only be deleted when a note ID is provided.
        """
        thread = ctx.thread

        try:
            await thread.delete_message(message_id, note=True)
        except ValueError as e:
            logger.warning("Failed to delete message: %s.", e)
            return await ctx.send(
                embed=discord.Embed(
                    title="Failed",
                    description="Cannot find a message to delete.",
                    color=self.bot.error_color,
                )
            )

        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def repair(self, ctx):
        """
        Repair a thread broken by Discord.
        """
        sent_emoji, blocked_emoji = await self.bot.retrieve_emoji()

        if ctx.thread:
            user_id = match_user_id(ctx.channel.topic)
            if user_id == -1:
                logger.info("Setting current channel's topic to User ID.")
                await ctx.channel.edit(topic=f"User ID: {ctx.thread.id}")
            return await self.bot.add_reaction(ctx.message, sent_emoji)

        logger.info("Attempting to fix a broken thread %s.", ctx.channel.name)

        # Search cache for channel
        user_id, thread = next(
            ((k, v) for k, v in self.bot.threads.cache.items() if v.channel == ctx.channel),
            (-1, None),
        )
        if thread is not None:
            logger.debug("Found thread with tempered ID.")
            await ctx.channel.edit(reason="Fix broken Modmail thread", topic=f"User ID: {user_id}")
            return await self.bot.add_reaction(ctx.message, sent_emoji)

        # find genesis message to retrieve User ID
        async for message in ctx.channel.history(limit=10, oldest_first=True):
            if (
                message.author == self.bot.user
                and message.embeds
                and message.embeds[0].color
                and message.embeds[0].color.value == self.bot.main_color
                and message.embeds[0].footer.text
            ):
                user_id = match_user_id(message.embeds[0].footer.text, any_string=True)
                other_recipients = match_other_recipients(ctx.channel.topic)
                for n, uid in enumerate(other_recipients):
                    other_recipients[n] = await self.bot.get_or_fetch_user(uid)

                if user_id != -1:
                    recipient = self.bot.get_user(user_id)
                    if recipient is None:
                        self.bot.threads.cache[user_id] = thread = Thread(
                            self.bot.threads, user_id, ctx.channel, other_recipients
                        )
                    else:
                        self.bot.threads.cache[user_id] = thread = Thread(
                            self.bot.threads, recipient, ctx.channel, other_recipients
                        )
                    thread.ready = True
                    logger.info("Setting current channel's topic to User ID and created new thread.")
                    await ctx.channel.edit(reason="Fix broken Modmail thread", topic=f"User ID: {user_id}")
                    return await self.bot.add_reaction(ctx.message, sent_emoji)

        else:
            logger.warning("No genesis message found.")

        # match username from channel name
        # username-1234, username-1234_1, username-1234_2
        m = re.match(r"^(.+)-(\d{4})(?:_\d+)?$", ctx.channel.name)
        if m is not None:
            users = set(
                filter(
                    lambda member: member.name == m.group(1) and member.discriminator == m.group(2),
                    ctx.guild.members,
                )
            )
            if len(users) == 1:
                user = users.pop()
                name = self.bot.format_channel_name(user, exclude_channel=ctx.channel)
                recipient = self.bot.get_user(user.id)
                if user.id in self.bot.threads.cache:
                    thread = self.bot.threads.cache[user.id]
                    if thread.channel:
                        embed = discord.Embed(
                            title="Delete Channel",
                            description="This thread channel is no longer in use. "
                            f"All messages will be directed to {ctx.channel.mention} instead.",
                            color=self.bot.error_color,
                        )
                        embed.set_footer(
                            text='Please manually delete this channel, do not use "{prefix}close".'
                        )
                        try:
                            await thread.channel.send(embed=embed)
                        except discord.HTTPException:
                            pass

                other_recipients = match_other_recipients(ctx.channel.topic)
                for n, uid in enumerate(other_recipients):
                    other_recipients[n] = await self.bot.get_or_fetch_user(uid)

                if recipient is None:
                    self.bot.threads.cache[user.id] = thread = Thread(
                        self.bot.threads, user_id, ctx.channel, other_recipients
                    )
                else:
                    self.bot.threads.cache[user.id] = thread = Thread(
                        self.bot.threads, recipient, ctx.channel, other_recipients
                    )
                thread.ready = True
                logger.info("Setting current channel's topic to User ID and created new thread.")
                await ctx.channel.edit(
                    reason="Fix broken Modmail thread", name=name, topic=f"User ID: {user.id}"
                )
                return await self.bot.add_reaction(ctx.message, sent_emoji)

            elif len(users) >= 2:
                logger.info("Multiple users with the same name and discriminator.")
        return await self.bot.add_reaction(ctx.message, blocked_emoji)

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def enable(self, ctx):
        """
        Re-enables DM functionalities of Modmail.

        Undo's the `{prefix}disable` command, all DM will be relayed after running this command.
        """
        embed = discord.Embed(
            title="Success",
            description="Modmail will now accept all DM messages.",
            color=self.bot.main_color,
        )

        if self.bot.config["dm_disabled"] != DMDisabled.NONE:
            self.bot.config["dm_disabled"] = DMDisabled.NONE
            await self.bot.config.update()

        return await ctx.send(embed=embed)

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def disable(self, ctx):
        """
        Disable partial or full Modmail thread functions.

        To stop all new threads from being created, do `{prefix}disable new`.
        To stop all existing threads from DMing Modmail, do `{prefix}disable all`.
        To check if the DM function for Modmail is enabled, do `{prefix}isenable`.
        """
        await ctx.send_help(ctx.command)

    @disable.command(name="new")
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def disable_new(self, ctx):
        """
        Stop accepting new Modmail threads.

        No new threads can be created through DM.
        """
        embed = discord.Embed(
            title="Success",
            description="Modmail will not create any new threads.",
            color=self.bot.main_color,
        )
        if self.bot.config["dm_disabled"] < DMDisabled.NEW_THREADS:
            self.bot.config["dm_disabled"] = DMDisabled.NEW_THREADS
            await self.bot.config.update()

        return await ctx.send(embed=embed)

    @disable.command(name="all")
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def disable_all(self, ctx):
        """
        Disables all DM functionalities of Modmail.

        No new threads can be created through DM nor no further DM messages will be relayed.
        """
        embed = discord.Embed(
            title="Success",
            description="Modmail will not accept any DM messages.",
            color=self.bot.main_color,
        )

        if self.bot.config["dm_disabled"] != DMDisabled.ALL_THREADS:
            self.bot.config["dm_disabled"] = DMDisabled.ALL_THREADS
            await self.bot.config.update()

        return await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def isenable(self, ctx):
        """
        Check if the DM functionalities of Modmail is enabled.
        """

        if self.bot.config["dm_disabled"] == DMDisabled.NEW_THREADS:
            embed = discord.Embed(
                title="New Threads Disabled",
                description="Modmail is not creating new threads.",
                color=self.bot.error_color,
            )
        elif self.bot.config["dm_disabled"] == DMDisabled.ALL_THREADS:
            embed = discord.Embed(
                title="All DM Disabled",
                description="Modmail is not accepting any DM messages for new and existing threads.",
                color=self.bot.error_color,
            )
        else:
            embed = discord.Embed(
                title="Enabled",
                description="Modmail now is accepting all DM messages.",
                color=self.bot.main_color,
            )

        return await ctx.send(embed=embed)



    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 120, BucketType.user)
    async def wordle(self, ctx):

      word = Wordnik()
      #r = random_word.RandomWords()
      r = Wordnik(api_key="z50ig8roorenuuwsltd0y2wrq2v5yozey6bfbhgp87f4d7e41")
      new_word = r.get_random_word(
        hasDictionaryDef="true",
        includePartOfSpeech="noun",
        minLength=5, 
        maxLength=5
      ).lower()
      await ctx.send("Game started! Make a guess! *(You can end the game by saying `end`)*")
      print(f"{ctx.author}'s word is {new_word}")

      def check(m):
        return m.channel == ctx.channel and m.author == ctx.author

      grid = ""
      while ((guess := (await self.bot.wait_for('message', check=check)).content.lower()) != new_word):
        line = ""

        if re.search("(^cancel$)|(^end$)", guess):
          await ctx.send(f"{ctx.author.mention} gave up! Their word was: ||{new_word}||!")
          await ctx.message.add_reaction("<:aiko_success:965918214498443274>")
          break
        
        if len(guess) != 5:
          await ctx.send("Invalid word. Guess again!")          
        else:
          for expected, actual in zip(guess, new_word):
            if expected == actual:
              line += ":green_square:"
            elif expected in new_word:
              line += ":yellow_square:"
            else:
              line += ":black_large_square:"
          grid += f"{line}\n"
          await ctx.send(line)

      grid += ":green_square:" * 5
      await ctx.send(grid)


      if guess == new_word:
        await ctx.send(f"{ctx.author.mention} guessed the word **{new_word}** correctly!")



    class ThreadID(commands.Cog):
      """
      Get the user's ID.
      """

    def __init__(self, bot):
      self.bot = bot

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def id(self, ctx):
      """Returns the Recipient's ID"""
      await ctx.send(f"<@!{ctx.thread.id}> - {ctx.thread.id}")
		
    async def setup(bot):
	    await bot.add_cog(ThreadID(bot))


    @commands.command(aliases=["force-leave", "eval-kick", "leaveserver"])
    @checks.has_permissions(PermissionLevel.OWNER)
    @commands.cooldown(1, 60, BucketType.user)
    async def leaveguild(self, ctx, guild_id: int):
        """
        Force leave a server.
        """

        try:
            await self.bot.get_guild(guild_id).leave()
            await ctx.send(f"Left `{guild}` ({guild.id})")
            await ctx.message.add_reaction("<:aiko_success:965918214498443274>")
            return
        except:
            await ctx.send("Something went wrong.")
            await ctx.message.add_reaction("<:aiko_error:965918214171291659>")
            
            return


    MEMBER_ID_REGEX = re.compile(r'<@!?([0-9]+)>$')

    class MemberOrID(commands.IDConverter):
      async def convert(self, ctx: commands.Context, argument: str) -> typing.Union[discord.Member, discord.User]:
        result: typing.Union[discord.Member, discord.User]
        try:
            result = await commands.MemberConverter().convert(ctx, argument)
        except commands.BadArgument:
            match = self._get_id_match(argument) or MEMBER_ID_REGEX.match(argument)
            if match:
                try:
                    result = await ctx.bot.fetch_user(int(match.group(1)))
                except discord.NotFound as e:
                    raise commands.BadArgument(f'Member {argument} not found') from e
            else:
                raise commands.BadArgument(f'Member {argument} not found')

        return result

    class Moderation(commands.Cog): 
      """Mass ban tool"""
    
    def __init__(self, bot):
        self.bot = bot
        self.defaultColor = 0x2f3136
        self.db = bot.api.get_plugin_partition(self)

    @commands.command(usage='\u200b', aliases=["mban", "massban"])
    @checks.has_permissions(PermissionLevel.ADMIN)
    async def ban(self, ctx, members: commands.Greedy[discord.Member] = None, days: typing.Optional[int] = 1, *, reason: str = None) -> None:
        """*Mass-bans members*\n
        Info:
        ├─ `Members` - seperate by space.
        ├─ `Days` - deleted messages for number of days (optional; default is 1).
        └─ `Reason` - a reason."""
      
        config = await self.db.find_one({"_id": "config"})
        logs_channel = (os.getenv("channel"))
        setchannel = discord.utils.get(ctx.guild.channels, id=int(logs_channel))

        if members is None:
            return await ctx.send_help(ctx.command)

        banned = 0
        for member in members:
            embed = discord.Embed(color=self.defaultColor, timestamp=discord.utils.utcnow())
            if not isinstance(member, (discord.User, discord.Member)):
                member = await MemberOrID.convert(self, ctx, member)
            try:
                await member.ban(delete_message_days=days, reason=f"{reason if reason else None}")
                banned += 1
                embed.set_author(name=ctx.author.name, icon_url=ctx.author.avatar)
                embed.add_field(name="User", value=f"{member.mention} | {member}", inline=False)
                embed.add_field(name="Moderator", value=f"{ctx.author.mention} | ID {ctx.author.id}", inline=False)
                embed.add_field(name="Reason", value=reason, inline=False)
                embed.set_footer(text=f"User ID: {member.id}")

            except discord.Forbidden:
                embed.set_author(name=ctx.author.name, icon_url=ctx.author.avatar)
                embed.add_field(name="Failed", value=f"{member.mention} | {member}", inline=False)
                embed.add_field(name="Moderator", value=f"{ctx.author.mention} | ID {ctx.author.id}", inline=False)
                embed.add_field(name="Reason", value=reason, inline=False)
                embed.set_footer(text=f"User ID: {member.id}")

            except Exception as e:
                embed.add_field(name="Error", value=e, inline=False)

            await setchannel.send(embed=embed)

        await setchannel.send(
            embed=discord.Embed(color=self.defaultColor, description=(
            f"Banned {banned} {'members' if banned > 1 else 'member'}\n"
            f"Failed to ban {len(members)-banned} {'members' if len(members)-banned > 1 else 'member'}"
            )))

        try:
            await ctx.message.delete()
        except discord.errors.Forbidden:
            await ctx.send("Not enough permissions to delete messages.", delete_after=6)


    async def setup(bot):
      await bot.add_cog(Moderation(bot))


    class MuteCog(commands.Cog):
      def __init__(self, bot):
          self.bot = bot


    @commands.command(aliases=["timeout"], usage="[user] [time] (reason)")
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @commands.cooldown(1, 7, BucketType.user)
    async def mute(self, ctx, member:discord.Member, time, *, reason="None"):
        """
        Mute a member for up to 7 days (use "m" for minutes, "h" for hours and "d" for days).
        """

        channel = self.bot.get_channel(int(os.getenv("channel")))

        if reason != "None":
          reason=reason
        else:
          reason="No reason specified."

        if not re.search("(m$|h$|d$)", time):
          await ctx.send("Invalid time format (use `m` for minutes, `h` for hours and `d` for days).")
          ctx.command.reset_cooldown(ctx)
          return

        time_conversion = {"m": 60, "h": 3600, "d": 86400}
        mute_time = int(time[:-1]) * time_conversion[time[-1]]

        if mute_time > 604800:
          await ctx.send("You can only mute someone for up to 7 days.")
          ctx.command.reset_cooldown(ctx)
          return
      
        await member.timeout(discord.utils.utcnow() + datetime.timedelta(seconds=int(mute_time)), reason=reason)

        duration = discord.utils.utcnow() + datetime.timedelta(seconds=int(mute_time))
        duration = discord.utils.format_dt(duration, "f")

        await ctx.send(f"Muted {member} for {time}.")

        embed = discord.Embed(title="Mute", color=self.bot.main_color, timestamp = discord.utils.utcnow())

        embed.add_field(name="Moderator", value=f"{ctx.author.mention}", inline=False)
        embed.add_field(name="User", value=f"{member.mention}", inline=False)
        embed.add_field(name="Until", value=f"{duration}", inline=False)
        embed.add_field(name="Reason", value=f"{reason}", inline=False)

        embed.set_footer(text=f"User ID: {member.id}")

        await channel.send(embed=embed)


    @commands.command()
    @checks.has_permissions(PermissionLevel.MODERATOR)
    async def unmute(self, ctx, member:discord.Member):
      """
      Unmute a member, if they are muted.
      """

      channel = self.bot.get_channel(int(os.getenv("channel")))

      if member.is_timed_out() == False:
        await ctx.send("That user is not currently muted.")
        return

      await member.edit(timed_out_until=None)

      embed = discord.Embed(title="Unmute", color=self.bot.main_color, timestamp = discord.utils.utcnow())
      embed.add_field(name="Moderator", value=f"{ctx.author.mention}")
      embed.add_field(name="User", value=f"{member.mention}")
      embed.set_footer(text=f"User ID: {member.id}")
      await channel.send(embed=embed)

    async def setup(bot):
      await bot.add_cog(MuteCog(bot))


    @commands.command(usage="[limit]")
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @commands.cooldown(2, 240, BucketType.user)
    async def purge(self, ctx, amount: int = 0):
      """
      Purge up to 100 messages in the channel.
      """

      max = 100
      channel = self.bot.get_channel(int(os.getenv("channel")))

      if amount > max:
          return await ctx.send(f"{ctx.author.mention} you can only purge up to 100 messages.", delete_after=6)

      try:
          await ctx.message.delete()
          await ctx.channel.purge(limit=amount)
      except discord.errors.Forbidden:
          return await ctx.send(f"{ctx.author.mention} I couldn't purge the messages.", delete_after=6)


      messages = "messages" if amount > 1 else "message"
      have = "have" if amount > 1 else "has"


      await ctx.send(f"Purged {amount} {messages}.", delete_after=8)
      embed = discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())
      embed.add_field(name="Purge", value=f"{ctx.author.mention} ({ctx.author}) purged {amount} {messages} in {ctx.channel.mention}.", inline=False)
      embed.set_footer(text=f"User ID: {ctx.author.id}")

      await channel.send(embed=embed)
      

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMIN)
    async def echo(self, ctx, channel: discord.TextChannel, *, msg: str):
      """
      Send a message through Aiko!
      """

      #channel = re.findall("", channel)

      #try:
      #channel = await self.bot.fetch_channel(int(channel))
      #except:
        #await ctx.send("Channel not found.")
        #return

      await channel.send(f"{msg}")
      await ctx.message.add_reaction("<:aiko_success:965918214498443274>")



    class webhooks(commands.Cog):
      def __init__(self, bot):
        self.bot = bot
        self._last_result = None

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def webhook(self, ctx, *, msg):
        """
       Make Aiko webhooks to say something.
        """

        webhook = await ctx.channel.create_webhook(name="aiko webhook")
        await webhook.send(content=msg, username=self.bot.user.name, avatar_url=self.bot.user.avatar.url)
        await webhook.delete()

        print(f"{ctx.author} used the webhook command and said: {msg}")

    async def setup(bot):
      await bot.add_cog(webhooks(bot))


    class wyr(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command(usage="[option 1] [option 2] (suggester)")
    @checks.has_permissions(PermissionLevel.MOD)
    #@commands.has_role(819234810543210496)
    @commands.cooldown(2, 36000, BucketType.guild)
    async def wyr(self, ctx, choice1, choice2, suggester: discord.Member = "None"):
      """
      A would you rather command, separate the choices with "".

      Template:
      <a:1whiteheart:801122446966128670> ⋆ Would you rather... *(by [user])*

      <a:1arrow:801122446874509352> ⋆ **Option 1**
      <a:1arrow:801122446874509352> ⋆ **Option 2**

      ⊹ ─── ⊹ ─── ⊹ ─── <@&760529762450931718> ─── ⊹ ─── ⊹ ─── ⊹
      """

      wyr_channel = self.bot.get_channel(1000806786447720548) # change
      choice1 = choice1.capitalize()
      choice2 = choice2.capitalize()

      if suggester != "None":
        suggester = self.bot.guild.get_member(suggester.id)
        suggester = suggester.mention
      else:
        suggester = ctx.author.mention
      
      await ctx.send(f"The message will look like this, send it? (yes/no)\n\n<a:1whiteheart:801122446966128670> ⋆ Would you rather... *(by {suggester})*\n\n<a:1arrow:801122446874509352> ⋆ **{choice1}**\n<a:1arrow:801122446874509352> ⋆ **{choice2}**\n\n⊹ ─── ⊹ ─── ⊹ ─── **[events]** ─── ⊹ ─── ⊹ ─── ⊹")

      def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
      
      try:
        response = await self.bot.wait_for('message', check=check, timeout=30)
      except:
        await ctx.message.add_reaction("<:aiko_error:965918214171291659>")
        ctx.command.reset_cooldown(ctx)
        return


      if response.content.lower() in ("yes", "y", "<:chibilapproval:818499768149999650>", "<:ddlcsayoricool:846778526740119625>", "ofc", "ye", "yeah", "yehs", "yesh", "mhm", "yea"):
        msg = await wyr_channel.send(f"<a:1whiteheart:801122446966128670> ⋆ Would you rather... *(by {suggester})*\n\n<a:1arrow:801122446874509352> ⋆ **{choice1}**\n<a:1arrow:801122446874509352> ⋆ **{choice2}**\n\n⊹ ─── ⊹ ─── ⊹ ─── **<@&760529762450931718>** ─── ⊹ ─── ⊹ ─── ⊹") 
        await msg.add_reaction("<:aiko_1:965916655878291507>")
        await msg.add_reaction("<:aiko_2:965916656536789052>")
      else:
        await ctx.send("Canceled.")
        ctx.command.reset_cooldown(ctx)
        return


    async def setup(bot):
      await bot.add_cog(wyr(bot))


    @commands.command(aliases=["namefix", "namesfix", "fixnames"])
    @checks.has_permissions(PermissionLevel.MOD)
    @commands.cooldown(1, 3600, BucketType.guild)
    async def fixname(self, ctx):

      total = 0
      for member in ctx.guild.members:
        if not re.search("([!-~])", str(member.name)) and not re.search("(^change nickname)|([!-~])", str(member.nick)):
          await member.edit(nick="change nickname!", reason="Unpingable Name")
          total += 1
      await ctx.channel.send(f"Changed the nickname of {total} users.")

    async def setup(bot):
      await bot.add_cog(automod_cmds(bot))


    class RebootCog(commands.Cog):
        def __init__(self, bot):
            self.bot = bot

    @commands.command()
    @checks.has_permissions(PermissionLevel.OWNER)
    @commands.cooldown(1, 3600, BucketType.guild)
    async def restart(self, ctx):
        """Clears Cached Logs & Reboots The Bot"""
        
        await ctx.send("Restarting...")

        os.execl(sys.executable, sys.executable, * sys.argv)
        exit()


    def setup(bot):
        bot.add_cog(RebootCog(bot))


    class partner(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def partner(self, ctx):

      partner = discord.utils.get(ctx.guild.roles, id=741774737168007219)   # change
      channel = self.bot.get_channel(int(os.getenv("channel")))
      member = ctx.guild.get_member(ctx.thread.id)


      embed=discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())
      embed.add_field(name="Role Added", value=f"{ctx.thread.recipient.mention} ({ctx.thread.recipient}) was given the {partner.mention} role by {ctx.author.mention} ({ctx.author}).")
      embed.set_footer(text=f"PM ID: {ctx.author.id} - User ID: {ctx.thread.recipient.id}")

      await member.add_roles(partner, reason="Partnership", atomic=True)
      await channel.send(embed=embed)
      await ctx.send(content=f"Gave {member.mention} the {partner.mention} role", allowed_mentions=discord.AllowedMentions(roles=False))

    async def setup(bot):
      await bot.add_cog(partner(bot))


    class customRole(commands.Cog):
        def __innit__(self, bot):
            self.bot = bot

    @commands.command(usage="[role name] [color] (role icon link)")
    @checks.has_permissions(PermissionLevel.ADMIN)
    @checks.thread_only()
    @commands.cooldown(1, 10, BucketType.user)
    async def custom(self, ctx, name, color: str, icon = None):
        """
        Give the user in the thread a custom role.
        
        *Notes:*
            ・ The role icon is optional.
            ・ If the role name is more than one word enclose it in " ".
            ・ Only use hex values for the color (i.e. #1a2748).
            ・ The role icon **needs** to be a link and end in either `.png` or `.jpg`.
        """

        member = ctx.guild.get_member(ctx.thread.id)
        color = discord.Color.from_str(color)
        embed=discord.Embed(title=f"Role assigned to {member}!", color=color, timestamp=discord.utils.utcnow())


        if icon != None:
            if not re.search("(\.png|\.jpg)$", icon):
                embed.description="Something went wrong. Keep in mind the image link needs to end in either `.png` or `.jpg`."
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(icon) as resp:

                        if resp.status != 200:
                            embed.description="Something went wrong."
                
                        else:
                            data = io.BytesIO(await resp.read())
                            icon = data.read()

                embed.set_thumbnail(url=icon)
            has_icon = "Yes"
        else:
            has_icon = "No"

        new_role = await ctx.guild.create_role(name=name, color=color, display_icon=icon, reason=f"Custom role for {member} by {ctx.author}")
        await new_role.edit(position=100)
        await member.add_roles(new_role, reason=f"Custom role for {member} by {ctx.author}", atomic=True)

        embed.description = f"Role: {new_role.mention} ({new_role.name})\nColor: {color}\nHas role icon: {has_icon}"
        embed.set_footer(text=f"Role ID: {new_role.id} | Created by {ctx.author}")

        await ctx.send(embed=embed)



    async def setup(bot):
        await bot.add_cog(customRole(bot))

    class rules(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.MOD)
    @trigger_typing
    @commands.cooldown(1, 10, BucketType.user)
    async def rules(self, ctx):
      """
      Displays every unverified member that has been in the server for more than 10 hours.
      """

      role = discord.utils.get(ctx.guild.roles, id=648641822431903784)  # change
      count = 0
      message = ""


      for member in ctx.guild.members:
        if member.bot == False and role not in member.roles:

          today = discord.utils.utcnow()
          delta = int(((today - member.joined_at).total_seconds())/3600)
          
          if delta >= 10:
            message += f"{member.mention} - `{delta} hours ago`\n"
            count += 1
        
      if count > 0:
        top_message = "Every unverified member that has been in the server for more than 10h, use **!rules kick** to kick them."
        await ctx.send(top_message)
        await ctx.send(message)
      else:
        top_message = "There are no unverified members that have been in the server for more than 10 hours."
        await ctx.send(top_message)
      

    @rules.command(name="kick")
    @checks.has_permissions(PermissionLevel.MOD)
    @trigger_typing
    @commands.cooldown(1, 120, BucketType.guild)
    async def rules_kick(self, ctx):
      """
      Kicks every unverified member that has been in the server for more than 10 hours.
      """

      role = discord.utils.get(ctx.guild.roles, id=648641822431903784)  # change
      count = 0
      
      for member in ctx.guild.members:
        if member.bot == False and role not in member.roles:

          today = discord.utils.utcnow()
          delta = int(((today - member.joined_at).total_seconds())/3600)

          if delta >= 10:

            try:
                await member.send(f"Didn't verify | Join again using this invite discord.gg/HWEc5bwJJC <:bearheart2:779833250649997313>")
            except discord.Forbidden:
                pass
            await member.kick(reason="Didn't verify")
            count += 1

      if count == 1:
        await ctx.channel.send(f"Kicked {count} unverified member.")
      else:
        await ctx.channel.send(f"Kicked {count} unverified members.")


    @rules.command(name="kick-all")
    @checks.has_permissions(PermissionLevel.MOD)
    @trigger_typing
    @commands.cooldown(1, 600, BucketType.guild)
    async def rules_kick_all(self, ctx):
      """
      Kicks every unverified member.
      """

      role = discord.utils.get(ctx.guild.roles, id=648641822431903784)  # change
      count = 0
      
      for member in ctx.guild.members:
        if member.bot == False and role not in member.roles:
            try:
                await member.send(f"Didn't verify | Join again using this invite discord.gg/HWEc5bwJJC <:bearheart2:779833250649997313>")
            except discord.Forbidden:
                pass
            await member.kick(reason="Didn't verify (kick-all)")
            count += 1

      if count == 1:
        await ctx.channel.send(f"Kicked {count} unverified member.")
      else:
        await ctx.channel.send(f"Kicked {count} unverified members.")

    @rules.command(name="user")
    @checks.has_permissions(PermissionLevel.MOD)
    @trigger_typing
    @commands.cooldown(1, 10, BucketType.guild)
    async def rules_user(self, ctx, member: discord.Member):
      """
      Kicks a specific unverified member.
      """

      role = discord.utils.get(ctx.guild.roles, id=648641822431903784)  # change

      if member.bot == False and role not in member.roles:
        try:
            await member.send(f"Didn't verify | Join again using this invite discord.gg/HWEc5bwJJC <:bearheart2:779833250649997313>")
        except discord.Forbidden:
            pass
        await member.kick(reason="Didn't verify (user)")

      await ctx.send(f"Kicked {member}")


    @rules.command(name="ban-all")
    @checks.has_permissions(PermissionLevel.ADMIN)
    @trigger_typing
    @commands.cooldown(1, 600, BucketType.guild)
    async def rules_ban(self, ctx):
      """
      Bans every unverified member.
      """

      role = discord.utils.get(ctx.guild.roles, id=648641822431903784)  # change
      count = 0

      for member in ctx.guild.members:
        if member.bot == False and role not in member.roles:
            await member.ban(reason="Mass-banned by the rules command.", delete_message_days=1)
            count += 1

      if count == 1:
        await ctx.send(f"Banned {count} unverified member.")
      else:
        await ctx.send(f"Banned {count} unverified members.")


    @rules.command(name="raw")
    @checks.has_permissions(PermissionLevel.MOD)
    @trigger_typing
    @commands.cooldown(1, 10, BucketType.user)
    async def rules_raw(self, ctx):
      """
      Displays a raw list of ID's for every unverified member that has been in the server for more than 10 hours.
      """

      role = discord.utils.get(ctx.guild.roles, id=648641822431903784)  # change
      message = "```\n"


      for member in ctx.guild.members:
        if member.bot == False and role not in member.roles:

          today = discord.utils.utcnow()
          delta = int(((today - member.joined_at).total_seconds())/3600)

          if delta >= 10:
            message += f"{member.id}\n"

      message += "```"
      await ctx.channel.send(message)

    @rules.command(name="all")
    @checks.has_permissions(PermissionLevel.MOD)
    @trigger_typing
    @commands.cooldown(1, 15, BucketType.user)
    async def rules_all(self, ctx):
      """
      Displays every unverified member in the server.
      """

      role = discord.utils.get(ctx.guild.roles, id=648641822431903784)  # change
      message = "Every unverified member in the server.\n\n"

      for member in ctx.guild.members:
        if member.bot == False and role not in member.roles:

          today = discord.utils.utcnow()
          delta = int(((today - member.joined_at).total_seconds())/3600)
          
          message += f"{member.mention} - `{delta} hours ago`\n"
      await ctx.channel.send(message)


    async def setup(bot):
      await bot.add_cog(rules(bot))



    class customRoles(commands.Cog):
      def __init__(self, bot):
        self.bot = bot


    @commands.command(aliases=["mycolour"], cooldown_after_parsing=True, usage="[hex]")
    @checks.has_permissions(PermissionLevel.REGULAR)
    @trigger_typing
    @commands.cooldown(1, 15, BucketType.user)
    async def mycolor(self, ctx, clr):

      """
      Change the color of your custom role!
      """

      channel = self.bot.get_channel(int(os.getenv("channel")))

      winter = discord.utils.get(ctx.guild.roles, id=808860767050530823)  # change
      cinni = discord.utils.get(ctx.guild.roles, id=905070283851968603)  # change
      realist = discord.utils.get(ctx.guild.roles, id=905199204060786711)  # change
      emy = discord.utils.get(ctx.guild.roles, id=923331031111712868)  # change
      dis = discord.utils.get(ctx.guild.roles, id=1004176857849155614)  # change
      soti = discord.utils.get(ctx.guild.roles, id=771879416061886495)  # change
      lillie = discord.utils.get(ctx.guild.roles, id=891821208646086708)  # change
      star = discord.utils.get(ctx.guild.roles, id=801202456499060737)  # change
      lina = discord.utils.get(ctx.guild.roles, id=767441062255001653)  # change
      vera = discord.utils.get(ctx.guild.roles, id=790043781473763351)  # change
      voter = discord.utils.get(ctx.guild.roles, id=973539832829730856)  # change


      if re.search("(random)$", clr):
        clr = random.randint(0,16777215)
        clr = "#" + (str(hex(clr)))[2:]

      if not re.search("(^#)", clr):
        clr = f"#{clr}"

      clr = discord.Color.from_str(clr)
      embed=discord.Embed(color=clr)

      if winter in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {winter.mention} role to {clr}.", inline=False)
          await winter.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif cinni in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {cinni.mention} role to {clr}.", inline=False)
          await cinni.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)
      
      elif realist in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {realist.mention} role to {clr}.", inline=False)
          await realist.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif emy in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {emy.mention} role to {clr}.", inline=False)
          await emy.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif dis in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {dis.mention} role to {clr}.", inline=False)
          await dis.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif soti in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {soti.mention} role to {clr}.", inline=False)
          await soti.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif lillie in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {lillie.mention} role to {clr}.", inline=False)
          await lillie.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif star in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {star.mention} role to {clr}.", inline=False)
          await star.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif lina in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {lina.mention} role to {clr}.", inline=False)
          await lina.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)

      elif vera in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {vera.mention} role to {clr}.", inline=False)
          await vera.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
          await channel.send(embed=embed)
      

      elif voter in ctx.author.roles and (winter and cinni and realist and emy and dis and soti and lillie and star and lina and vera not in ctx.author.roles):
        embed.add_field(name="Color Changed", value=f"Changed the color of the {voter.mention} role to {clr}.", inline=False)
        await voter.edit(color = clr, reason = f"Custom role color change by {ctx.author}")
        await channel.send(embed=embed)

      else:
        embed.colour = discord.Color.from_rgb(47, 49, 54)
        embed.add_field(name="No custom role found!", value=f"Head to <#741835235737731083> to learn how to get a custom role!", inline=False)

      await ctx.channel.send(embed=embed)


    async def setup(bot):
      await bot.add_cog(customRoles(bot))



    class partnerships(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.group(aliases=["p", "pm"], usage="(member)", invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @trigger_typing
    @commands.cooldown(1, 5, BucketType.user)
    async def partnerships(self, ctx, member: discord.Member = "None"):
      """
      See how many partnerships you or another PM has posted.
      """

      embed = discord.Embed(color=0x2f3136, timestamp=discord.utils.utcnow())
      pms = discord.utils.get(ctx.guild.roles, id=751470169448120422)  # change
      links = self.bot.get_channel(651753340623126538) # change
      count = 0
      
      if member != "None":
        member = self.bot.guild.get_member(member.id)
      else:
        member = ctx.author

      if pms in member.roles:
        async for message in links.history(limit=2000):
            if message.author == member:
                count += 1
        msg = f"{member.mention} has posted {count} partnerships!"
      else:
        msg = "That user is not a PM!"

      embed.add_field(name="Partnership Count!", value=msg)

      await ctx.reply(embed=embed)

    @partnerships.command(name="lb")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @trigger_typing
    @commands.cooldown(1, 5, BucketType.user)
    async def partner_lb(self, ctx):
      """
      See who has posted the most partnerships!
      """

      pms = discord.utils.get(ctx.guild.roles, id=751470169448120422)  # change
      embed = discord.Embed(color=0x2f3136, timestamp=discord.utils.utcnow())
      links = self.bot.get_channel(651753340623126538) # change
      msg = "**Partnerships leaderboard!**\n\n"

      for member in ctx.guild.members:
        count = 0
        if pms in member.roles:
            async for message in links.history(limit=2000):
                if message.author == member:
                    count += 1
            msg += f"{member.mention} → {count}\n"

      embed.description = msg
      await ctx.channel.send(embed=embed)


    async def setup(bot):
      await bot.add_cog(partnerships(bot))

    class Fun(commands.Cog):
      def __init__(self, bot):
          self.bot = bot

    @commands.group(aliases=["av"], usage="(member)", invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 5, BucketType.user)
    async def avatar(self, ctx, member: discord.User = "None"):
        """
        Get your or another user's avatar.
        """

        if member != "None":
            member = await self.bot.fetch_user(member.id)
        else:
            member = ctx.author

        embed=discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())
        embed.title=f"{member.name}'s avatar"
        embed.set_footer(text=f"ID: {member.id}")
        embed.set_image(url=member.avatar.url)

        await ctx.send(embed=embed)
    
    @avatar.command(name="guild", aliases=["server"])
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 5, BucketType.user)
    async def av_guild(self, ctx, member: discord.Member = "None"):
        """
        Get your or another user's server avatar, if it exists.
        """

        if member != "None":
            member = self.bot.guild.get_member(member.id)
        else:
            member = ctx.author

        embed=discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())

        if member.display_avatar.url == member.avatar.url:
            embed.title=f"{member.name} doesn't have a server avatar!"
        else:
            embed.title=f"{member.name}'s server avatar"
            embed.set_image(url=member.avatar.url)

        embed.set_footer(text=f"ID: {member.id}")

        await ctx.send(embed=embed)


    @commands.command(usage="(member)")
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 5, BucketType.user)
    async def banner(self, ctx, member: discord.User = "None"):
        """
        Get your or another user's banner.
        """

        embed=discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())

        if member != "None":
            member = await self.bot.fetch_user(member.id)
        else:
            member = ctx.author


        if member.banner != None:
            embed.title=f"{member.name}'s banner"
            embed.set_footer(text=f"ID: {member.id}")
            embed.set_image(url=member.banner.url)
        else:
            embed.title=f"{member.name} doesn't have a banner!"

        await ctx.send(embed=embed)


    @commands.command(usage="(member)", aliases=["userinfo", "w"])
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 5, BucketType.user)
    async def whois(self, ctx, *, member: discord.User = "None"):
        """
        Get a user's info.
        """

        if member != "None":
            try:
                member = await self.bot.get_user(member.id)
                in_server = True
            except:
                member = await self.bot.fetch_user(member.id)
                in_server = False
        else:
            member = ctx.author
            in_server = True

        embed=discord.Embed(color=member.color, title=f"{member.name}'s profile", timestamp=discord.utils.utcnow())
        embed.set_thumbnail(url=member.avatar.url)
        embed.set_footer(text=f"ID: {member.id}")
        embed.add_field(name="Mention", value=member.mention)
        embed.add_field(name="Username", value=member.name)

        if in_server == False:
            embed.description = "This user is not in the server"
        else:
            embed.description = "This user is in the server"
            embed.add_field(name="Joined Server", value=discord.utils.format_dt(member.joined_at, "F"))

        if member.bot == True:
            embed.description += " and is a bot."
        else:
            embed.description += " and is not a bot."
        
        embed.add_field(name="Account Created", value=discord.utils.format_dt(member.created_at, "F"))

        await ctx.send(embed=embed)

    @commands.command(usage="[role]")
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 5, BucketType.user)
    async def roleinfo(self, ctx, *, role: discord.Role):
        """
        Get a role's stats.
        """

        rolecolor = str(role.color).upper()

        embed = discord.Embed(color=role.color)

        embed.set_author(name=f"Stats about {role.name}")

        embed.add_field(name="Role Name", value=f"{role.name}")
        embed.add_field(name="Color", value=rolecolor)
        embed.add_field(name="Members", value=len(role.members))
        embed.add_field(name="Created at", value=discord.utils.format_dt(role.created_at, "f"))
        embed.add_field(name="Role Position", value=role.position)
        embed.add_field(name="Mention", value=role.mention)
        embed.add_field(name="Hoisted", value=role.hoist)
        embed.add_field(name="Mentionable", value=role.mentionable)
        embed.add_field(name="Managed", value=role.managed)

        embed.set_footer(text=f"Role ID: {role.id}")

        await ctx.send(embed=embed)


    @commands.command(aliases=["guildinfo"])
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 5, BucketType.user)
    async def serverinfo(self, ctx):
        """
        Get the server's stats.
        """

        g = ctx.guild

        bots = len([m for m in g.members if m.bot])
        humans = len([m for m in g.members if not m.bot])
        online = len([m for m in g.members if m.status == discord.Status.online])
        idle = len([m for m in g.members if m.status == discord.Status.idle])
        dnd = len([m for m in g.members if m.status == discord.Status.dnd])

        embed = discord.Embed(color=self.bot.main_color)

        embed.set_author(name=f"{g.name}'s Stats")

        embed.add_field(
            name=f"Member Count",
            value=f"Online: {online}\nIdle: {idle}\nDND: {dnd}\nHumans: {humans}\nBots: {bots}\nMember Count: {g.member_count}",
        )
        embed.add_field(name="Categories", value=len(g.categories))
        embed.add_field(name="Text Channels", value=len(g.text_channels))
        embed.add_field(name="Voice Channels", value=len(g.voice_channels))
        embed.add_field(name="Roles", value=len(g.roles))
        embed.add_field(name="Server Owner", value=g.owner.mention)
        embed.add_field(name="Boost Count", value=g.premium_subscription_count)
        embed.add_field(name="Created", value=discord.utils.format_dt(g.created_at, "f"))

        embed.set_thumbnail(url=str(g.icon))
        embed.set_footer(text=f"Server ID: {g.id}")

        await ctx.send(embed=embed)


    @commands.command(aliases=["emote"], usage="[emoji]")
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 10, BucketType.user)
    async def emoji(self, ctx, *, emoji: discord.Emoji):
        """
        Get an emoji's stats.
        """

        e: discord.Emoji = self.emoji

        embed = discord.Embed(color=self.bot.main_color)
        
        emote = await e.guild.fetch_emoji(e.id)
        if emote.user:
            embed.add_field(name="Creator", value=emote.user.mention)
            embed.add_field(name="Creator's ID", value=emote.user.id)

        embed.set_author(name=f"{e.name.title()}'s Stats")

        embed.add_field(name="Created", value=discord.utils.format_dt(e.created_at, "f"))
        embed.add_field(name="Animated", value=e.animated)
        embed.add_field(name="Managed", value=e.managed)

        embed.set_thumbnail(url=str(e.url))
        embed.set_footer(text=f"Emoji ID: {e.id}")

        await ctx.send(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 5, BucketType.user)
    async def choose(self, ctx, *choices):
        """
        Choose between a few options (use "" to define the options).
        """

        for c in choices:
            choices = [c for c in choices]
        embed = discord.Embed(color=ctx.author.color)
        if len(choices) < 2:
            embed.description="You need to specify at least 2 options!"
        else:
            embed.title="I choose"
            embed.description=(choice(choices))

        await ctx.reply(embed=embed)

    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 3, BucketType.user)
    async def flip(self,ctx):
        """Flip a coin"""
        answer = choice(["heads", "tails"])
        await ctx.reply(f"It landed on **{answer}**!")

    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 10, BucketType.user)
    async def reverse(self, ctx, *, text):
        """!txeT ruoY esreveR"""

        embed=discord.Embed(color=ctx.author.color)

        text =  "".join(list(reversed(str(text))))
        embed.description=text

        await ctx.reply(embed=embed)

    @commands.command(usage="(member)")
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 10, BucketType.user)
    async def roast(self, ctx,*, user: discord.Member = "None"):
        """
        Roast someone! If you suck at roasting them yourself.
        """

        if user != "None":
            msg = f"Hey, {user.mention}!"
        else:
            user = ctx.author
            msg = ""

        roasts = ["I'd give you a nasty look but you've already got one.", "If you're going to be two-faced, at least make one of them pretty.", "It looks like your face caught fire and someone tried to put it out with a hammer.", "Scientists say the universe is made up of neutrons, protons and electrons. They forgot to mention morons.", "Why is it acceptable for you to be an idiot but not for me to point it out?", "Just because you have one doesn't mean you need to act like one.", "Someday you'll go far... and I hope you stay there.", "No, those pants don't make you look fatter - how could they?", "Save your breath - you'll need it to blow up your date.", "If you really want to know about mistakes, you should ask your parents.", "Whatever kind of look you were going for, you missed.", "I don't know what makes you so stupid, but it really works.", "You are proof that evolution can go in reverse.", "Brains aren't everything. In your case they're nothing.", "I thought of you today. It reminded me to take the garbage out.", "You're so ugly when you look in the mirror, your reflection looks away.", "Quick - check your face! I just found your nose in my business.", "It's better to let someone think you're stupid than open your mouth and prove it.", "You're such a beautiful, intelligent, wonderful person. Oh I'm sorry, I thought we were having a lying competition.", "I'd slap you but I don't want to make your face look any better.", "You have the right to remain silent because whatever you say will probably be stupid anyway."]

        if str(user.id) == str(ctx.bot.user.id):
            return await ctx.send(f"Nice try. Instead I am going to roast you now.\n\n {ctx.author.mention} {choice(roasts)}")

        await ctx.reply(f"{msg} {choice(roasts)}")

    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 10, BucketType.user)
    async def smallcaps(self, ctx, *, message):
        """
        ᴄᴏɴᴠᴇʀᴛ ʏᴏᴜʀ ᴛᴇxᴛ ᴛᴏ ꜱᴍᴀʟʟ ᴄᴀᴘꜱ!!
        """
        alpha = list(string.ascii_lowercase)     
        converter = ['ᴀ', 'ʙ', 'ᴄ', 'ᴅ', 'ᴇ', 'ꜰ', 'ɢ', 'ʜ', 'ɪ', 'ᴊ', 'ᴋ', 'ʟ', 'ᴍ', 'ɴ', 'ᴏ', 'ᴘ', 'ǫ', 'ʀ', 'ꜱ', 'ᴛ', 'ᴜ', 'ᴠ', 'ᴡ', 'x', 'ʏ', 'ᴢ']
        new = ""
        exact = message.lower()
        for letter in exact:
            if letter in alpha:
                index = alpha.index(letter)
                new += converter[index]
            else:
                new += letter
        await ctx.reply(new)

    @commands.command(aliases=["soti"])
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 10, BucketType.user)
    async def cringe(self, ctx, *, message):
        """
        mAkE ThE TeXt cRiNgY!!
        """
        text_list = list(message) #convert string to list to be able to edit it

        for i in range(0,len(message)):
            if i % 2 == 0:
                text_list[i]= text_list[i].lower()
            else:
                text_list[i]=text_list[i].upper()

        message = "".join(text_list) #convert list back to string(message) to print it as a word

        await ctx.reply(message)

    @commands.command()
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 3, BucketType.user)
    async def roll(self, ctx, number: int = 6):
        """Roll a random number.
        The result will be between 1 and `<number>`.
        `<number>` defaults to 6.
        """

        author = ctx.author

        if number > 1:
            n = randint(1, number)
            await ctx.reply(":game_die: {n} :game_die:".format(author=author, n=n))
        else:
            await ctx.reply(("Maybe higher than 1?").format(author=author))

    async def setup(bot):
      await bot.add_cog(Fun(bot))


    @commands.group(aliases=["avset"], usage="[avatar link]]", invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.ADMIN)
    @commands.cooldown(1, 300, BucketType.guild)
    async def setav(self, ctx, av):
        """
        Change Aiko's avatar.
        """

        embed = discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())
        embed.set_footer(text=f"Requested by {ctx.author}")

        if not re.search("(\.png|\.jpg)$", av):
            embed.description="Something went wrong. Keep in mind the image link needs to end in either `.png` or `.jpg`."
            await ctx.send(embed=embed)
            return

        async with aiohttp.ClientSession() as session:
            async with session.get(av) as resp:

                if resp.status != 200:
                    embed.description="Something went wrong."
                
                else:
                    embed.title = "Changed Aiko's avatar to:"
                    embed.set_image(url=av)
                    data = io.BytesIO(await resp.read())
                    av = data.read()

        await self.bot.user.edit(avatar=av)
        await ctx.send(embed=embed)

    @setav.group(name="revert", aliases=["reset"])
    @checks.has_permissions(PermissionLevel.ADMIN)
    @commands.cooldown(1, 300, BucketType.guild)
    async def setav_revert(self, ctx):
        """
        Revert Aiko's avatar to her default one.
        """

        embed = discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())
        embed.set_footer(text=f"Requested by {ctx.author}")


        async with aiohttp.ClientSession() as session:
            async with session.get("https://cdn.discordapp.com/avatars/865700778622713886/837d46e9c7e38a0b600ae654eaca1f35.png?size=1024") as resp:

                if resp.status != 200:
                    embed.description="Something went wrong."
                
                else:
                    embed.title = "Reverted Aiko's avatar."
                    data = io.BytesIO(await resp.read())
                    av = data.read()

        await self.bot.user.edit(avatar=av)
        await ctx.send(embed=embed)


    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMIN)
    @commands.cooldown(1, 3600, BucketType.guild)
    async def theme(self, ctx):
        """
        Change the channel names based on the pre-selected theme (this won't change private cateogries and some other channels).
        """

        emoji1 = "🎃"
        emoji2 = "🍬"
        emoji3 = "🦇"
        emoji4 = "🌜"
        emoji5 = "🍭"
        emoji6 = "🍫"
        emoji7 = "🦉"
        emoji8 = "🕷️"

        hello_cat = ctx.guild.get_channel(641780013003440178)
        com_cat = ctx.guild.get_channel(740595824639082576)
        general_cat = ctx.guild.get_channel(641449164328140804)
        play_cat = ctx.guild.get_channel(763825244581920838)
        calls_cat = ctx.guild.get_channel(688115144693121041)
        partner_cat = ctx.guild.get_channel(808781797718097971)
        stats_cat = ctx.guild.get_channel(741087382010462289)

        staff_apps = ctx.guild.get_channel(973718907221319760)

        newbies = ctx.guild.get_channel(641780135996948480)
        rules_fake = ctx.guild.get_channel(950180899310428280)
        rules = ctx.guild.get_channel(760498694323044362)
        intros = ctx.guild.get_channel(757681621171306676)
        roles = ctx.guild.get_channel(760500989614227496)
        crayons = ctx.guild.get_channel(760159326693752879)

        info = ctx.guild.get_channel(741835235737731083)
        mailbox = ctx.guild.get_channel(646476610853273601)
        meow = ctx.guild.get_channel(808786532173480036)
        bot_news = ctx.guild.get_channel(750476824433262674)
        cookies = ctx.guild.get_channel(741428273191583854)
        wyr = ctx.guild.get_channel(1000806786447720548)
        feedback = ctx.guild.get_channel(709969553026711562)

        main = ctx.guild.get_channel(641449164328140806)
        media = ctx.guild.get_channel(642840124505456641)
        selfies = ctx.guild.get_channel(798216652964495400)
        arts = ctx.guild.get_channel(703757494949773403)
        vent = ctx.guild.get_channel(683780684007079981)

        promo = ctx.guild.get_channel(769582489421217822)
        count = ctx.guild.get_channel(653055287510433824)
        cursed = ctx.guild.get_channel(660484550316523549)
        spam = ctx.guild.get_channel(641777941818245160)
        bots = ctx.guild.get_channel(949772478937440346)

        vc_room = ctx.guild.get_channel(741726855849050143)
        playlist = ctx.guild.get_channel(657012154699874324)
        chit_chat = ctx.guild.get_channel(642131623638204416)
        music = ctx.guild.get_channel(645740142752956416)
        music2 = ctx.guild.get_channel(949770280706899998)
        people2 = ctx.guild.get_channel(786590934099820544)
        people3 = ctx.guild.get_channel(788056412550070292)

        req = ctx.guild.get_channel(741333159274086400)
        links = ctx.guild.get_channel(651753340623126538)

        members = ctx.guild.get_channel(976869277355356230)
        goal = ctx.guild.get_channel(749308698047807578)

        msg = await ctx.send("Editing the channels/categories, this will take some time!")

        await hello_cat.edit(name=f"꒰ {emoji1} ꒱ helloo! ୨୧")
        await asyncio.sleep(2)
        await com_cat.edit(name=f"꒰ {emoji1} ꒱ community ୨୧")
        await asyncio.sleep(2)
        await general_cat.edit(name=f"꒰ {emoji1} ꒱ general ୨୧")
        await asyncio.sleep(2)
        await play_cat.edit(name=f"꒰ {emoji1} ꒱ playground ୨୧")
        await asyncio.sleep(2)
        await calls_cat.edit(name=f"꒰ {emoji1} ꒱ calls ୨୧")
        await asyncio.sleep(2)
        await partner_cat.edit(name=f"꒰ {emoji1} ꒱ partner ୨୧")
        await asyncio.sleep(2)
        await stats_cat.edit(name=f"꒰ {emoji1} ꒱ stats ୨୧")
        await asyncio.sleep(2)

        await staff_apps.edit(name=f"{emoji7}੭┆staff-apps！")
        await asyncio.sleep(2)

        await newbies.edit(name=f"୨{emoji5}ɞ﹕newbies")
        await asyncio.sleep(2)
        await rules_fake.edit(name=f"{emoji1}┆rules-ˊˎ")
        await asyncio.sleep(2)
        await rules.edit(name=f"{emoji1}┆rulesˊˎ")
        await asyncio.sleep(2)
        await intros.edit(name=f"╭ʚ{emoji3}﹕intros")
        await asyncio.sleep(2)
        await roles.edit(name=f"{emoji8}੭┆roles・٩ˊᗜˋو")
        await asyncio.sleep(2)
        await crayons.edit(name=f"╰ʚ{emoji2}﹕crayons")
        await asyncio.sleep(2)

        await info.edit(name=f"๑{emoji8}・info")
        await asyncio.sleep(2)
        await mailbox.edit(name=f"╭ʚ{emoji1}﹕mailbox")
        await asyncio.sleep(2)
        await meow.edit(name=f"{emoji7}੭┆meow！♡")
        await asyncio.sleep(2)
        await bot_news.edit(name=f"╰ʚ{emoji5}﹕bot-news")
        await asyncio.sleep(2)
        await cookies.edit(name=f"{emoji4}┆cookies•₊°")
        await asyncio.sleep(2)
        await wyr.edit(name=f"๑{emoji2}・wyr")
        await asyncio.sleep(2)
        await feedback.edit(name=f"{emoji3}┆feedback•₊°")
        await asyncio.sleep(2)

        await main.edit(name=f"୨{emoji1}ɞ﹕main")
        await asyncio.sleep(2)
        await media.edit(name=f"{emoji2}┆mediaˊˎ")
        await asyncio.sleep(2)
        await selfies.edit(name=f"{emoji4}┆selfiesˊˎ")
        await asyncio.sleep(2)
        await arts.edit(name=f"୨{emoji5}ɞ﹕arts-n-crafts")
        await asyncio.sleep(2)
        await vent.edit(name=f"{emoji3}┆vent-n-rantˊˎ")
        await asyncio.sleep(2)

        await promo.edit(name=f"୨{emoji3}ɞ﹕promo")
        await asyncio.sleep(2)
        await count.edit(name=f"๑{emoji2}・123")
        await asyncio.sleep(2)
        await cursed.edit(name=f"{emoji8}┆cursed•₊°")
        await asyncio.sleep(2)
        await spam.edit(name=f"{emoji7}┆spam•₊°")
        await asyncio.sleep(2)
        await bots.edit(name=f"๑{emoji1}・bots")
        await asyncio.sleep(2)

        await vc_room.edit(name=f"๑{emoji1}・vc-room")
        await asyncio.sleep(2)
        await playlist.edit(name=f"{emoji3}┆playlist•₊°")
        await asyncio.sleep(2)
        await chit_chat.edit(name=f"꒰꒰ {emoji1} chit chat")
        await asyncio.sleep(2)
        await music.edit(name=f"꒰꒰ {emoji1} moosic")
        await asyncio.sleep(2)
        await music2.edit(name=f"꒰꒰ {emoji1} moosic 2")
        await asyncio.sleep(2)
        await people2.edit(name=f"꒰꒰ {emoji1} 2 buddies :D")
        await asyncio.sleep(2)
        await people3.edit(name=f"꒰꒰ {emoji1} 3 buddies :D")
        await asyncio.sleep(2)

        await req.edit(name=f"╭ʚ{emoji1}﹕req")
        await asyncio.sleep(2)
        await links.edit(name=f"╰ʚ{emoji4}﹕links・๑•͈ᴗ•͈")
        await asyncio.sleep(2)

        await members.edit(name=f"꒰꒰ {emoji1} members: 750")
        await asyncio.sleep(2)
        await goal.edit(name=f"꒰꒰ {emoji1} goal: 850")

        await msg.edit(content="Finished editing the channels!")


    @commands.group(invoke_without_command=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @commands.cooldown(1, 10, BucketType.user)
    async def s(self, ctx):
      "See every snippet."

      p = "!!"
      embed=discord.Embed(color=self.bot.main_color, title="Server's Snippets")

      embed.description = f"{p}1boost\n{p}2boosts\n{p}status\n{p}ad\n{p}hi\n{p}noreply\n{p}proof\n{p}report\n{p}troll"
      embed.set_footer(text="To see what a snippet does run !s show [snippet name]")

      await ctx.send(embed=embed)

    @s.command(name="show", usage="[snippet name]")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @commands.cooldown(1, 5, BucketType.user)
    async def s_show(self, ctx, s: str):
        """
        See a snippet's response.
        """

        embed=discord.Embed(color=self.bot.main_color, title="Snippet Response", description="Replies with:\n\n")
        embed.set_footer(text=f"Requested by {ctx.author}")

        if re.search("1boost$", s):
            embed.description += "Thank you for boosting us! We have given you one free background for the </rank:981143682495434775> command! To redeem it head to <#949772478937440346> and use the </edit rank:981143682495434780> command, afterwards just find one you like and use the \"buy\" button! You also have the rest of the perks mentioned in <#741835235737731083>!"
        elif re.search("2boosts$", s):
            embed.description += "Thank you for boosting us twice!! We have given you two free backgrounds for the </rank:981143682495434775> command! To redeem them head to <#949772478937440346> and use the </edit rank:981143682495434780> command, afterwards just find one you like and use the \"buy\" button! You also got 2 free levels on top of the previous perks!\n\nAlso since you've boosted us twice you can get a custom role that you can change the color of whenever you want along with a role icon! What would you like to name it, what color should it have and do you want a role icon?"
        elif re.search("status$", s):
            embed.description += "Thank you for having a server invite in your status or about me, we have given you the **・ kewler member!₊˚ɞ** role (you can change its color using the `!mycolor` command)! Make sure to keep it there otherwise we'll remove the role!"
        elif re.search("ad$", s):
            embed.description = "Replies with the server's ad and gives the recipient the <@&741774737168007219> role."
        elif re.search("hi$", s):
            embed.description += "Hi! What can we help you with?"
        elif re.search("noreply$", s):
            embed.description += "Hey, we haven't heard from you in a bit <:c_sadbearcat:789175391704317952> If you don't respond soon the thread will be closed..."
        elif re.search("proof$", s):
            embed.description += "Please provide all the necessary proof if you're trying to report another user, such as message links, screenshots, full DM history etc. (what's considered necessary depends on what you're trying to report)."
        elif re.search("report$", s):
            embed.description += "Thanks for the report, we'll investigate and take action if needed!\n\nThe thread will be closed, if there's anything else you'd like to add please do so now, otherwise don't reply!"
        elif re.search("troll$", s):
            embed.description += "Aiko is not a place for you to play around, don't open threads for no actual reason or to joke around, this behavior regularly could result in a block or even potentially a ban from the server."
        else:
            embed.description = "Couldn't find that snippet."

        await ctx.reply(embed=embed)


    @commands.group(invoke_without_command=True, usage="")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 10, BucketType.user)
    async def closing(self, ctx):
        """
        Close the thread automatically after 5 minutes.
        """

        embed=discord.Embed(color=self.bot.main_color, title="Closing Thread", description="The thread will close in 5 minutes unless the user sends another message.", timestamp=discord.utils.utcnow())
        embed.set_footer(text="Cancel it with !closing cancel")

        if ctx.channel.category.id == 932000955581468682:   # change (and below)
            self.bot.config["log_channel_id"] = 959059849197531156
            await ctx.invoke(self.bot.get_command("freply"), msg = "We will now close this thread, replying will create a new one!")

        elif ctx.channel.category.id == 959059703357390868:
            self.bot.config["log_channel_id"] = 932001516754206820
            await ctx.invoke(self.bot.get_command("fareply"), msg = "We will now close this thread, replying will create a new one!")

        else:
            self.bot.config["log_channel_id"] = 959063351772717116
            await ctx.invoke(self.bot.get_command("fareply"), msg = "We will now close this thread, replying will create a new one!")


        await ctx.thread.close(silent=True, after=300, closer=ctx.author, message=None)
        await ctx.send(embed=embed)
        await asyncio.sleep(302)
        self.bot.config["log_channel_id"] = 932001516754206820


    @closing.command(name="now")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 10, BucketType.user)
    async def closing_now(self, ctx):
        """
        Close the thread immediately.
        """
        
        if ctx.channel.category.id == 932000955581468682:   # change (and below)
            self.bot.config["log_channel_id"] = 959059849197531156
            await ctx.invoke(self.bot.get_command("freply"), msg = "We will now close this thread, replying will create a new one!")

        elif ctx.channel.category.id == 959059703357390868:
            self.bot.config["log_channel_id"] = 932001516754206820
            await ctx.invoke(self.bot.get_command("fareply"), msg = "We will now close this thread, replying will create a new one!")

        else:
            self.bot.config["log_channel_id"] = 959063351772717116
            await ctx.invoke(self.bot.get_command("fareply"), msg = "We will now close this thread, replying will create a new one!")


        await ctx.thread.close(silent=True, after=0, closer=ctx.author, message=None)
        self.bot.config["log_channel_id"] = 932001516754206820


    @closing.command(name="silently", aliases=["silent"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 10, BucketType.user)
    async def closing_silent(self, ctx):
        """
        Close the thread immediately without notifying the user.

        *Note:* You should only use this subcommand when a user sends an insignificant message in a thread while pending to be closed, thus cancelling its closure.
        """
        
        if ctx.channel.category.id == 932000955581468682:   # change (and below)
            self.bot.config["log_channel_id"] = 959059849197531156

        elif ctx.channel.category.id == 959059703357390868:
            self.bot.config["log_channel_id"] = 932001516754206820

        else:
            self.bot.config["log_channel_id"] = 959063351772717116

        await ctx.thread.close(silent=True, after=0, closer=ctx.author, message=None)
        self.bot.config["log_channel_id"] = 932001516754206820


    @closing.command(name="cancel", aliases=["stop"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 15, BucketType.user)
    async def closing_cancel(self, ctx):
        """
        Cancel the automatic closure of a thread.
        """
        await ctx.invoke(self.bot.get_command("close"), option="cancel")



    @commands.command(usage="[message]")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 3, BucketType.user)
    async def say(self, ctx, *, msg: str = ""):
      "Reply in a thread."

      if ctx.channel.category.id == 932000955581468682: # change
        msg = self.bot.formatter.format(
            msg, channel=ctx.channel, recipient=ctx.thread.recipient, author=ctx.message.author
        )
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message)

      else:
        msg = self.bot.formatter.format(
            msg, channel=ctx.channel, recipient=ctx.thread.recipient, author=ctx.message.author
        )
        ctx.message.content = msg
        async with ctx.typing():
            await ctx.thread.reply(ctx.message, anonymous=True)

    
    @commands.command(aliases=["tot"])
    @checks.has_permissions(PermissionLevel.REGULAR)
    @commands.cooldown(1, 600, BucketType.user)
    async def trickortreat(self, ctx):
      "Trick or treat?"

      halloween = True

      if halloween == True:

        tricked = discord.utils.get(ctx.guild.roles, id=895808816703225916)    # change
        treated = discord.utils.get(ctx.guild.roles, id=895808709140299807)

        rng = random.randint(1, 29)
        clrs = ["#751a01", "#ae3204", "#e65104", "#ee9e20", "#f0c22c", "#541708", "#000000", "#09ff00", "#c900ff", "#a78eb8", "#2d341e", "#252c3c", "#f7cd82", "#c1d234", "#65141b", "#fe791a"]
        clr = random.choice(clrs)
        embed = discord.Embed(color=discord.Color.from_str(clr), title="Trick or Treat?")
        embed.set_footer(text="You can use the command again in 10 minutes!", icon_url="https://cdn.discordapp.com/emojis/1030326215187374142.gif?size=96&quality=lossless")

        if rng == 1 or rng == 2 or rng == 3 or rng == 4:    # mute

            admin = discord.utils.get(ctx.guild.roles, id=704792380624076820)  # change
            if admin in  ctx.author.roles:
                embed.description="You're lucky you're an admin... <:sus:653057730013167616>"
                await ctx.send(embed=embed)
                return

            mute_time = random.randint(1, 60)
            mute_time = readable_time = f"{mute_time}m"
            time_conversion = {"m": 60}
            mute_time = int(mute_time[:-1]) * time_conversion[mute_time[-1]]

            await ctx.author.timeout(discord.utils.utcnow() + datetime.timedelta(seconds=int(mute_time)), reason="Trick or Treat'd!")

            embed.description = f"You tried but... you got tricked and muted for {readable_time}!"
            embed.remove_footer()

        elif rng == 5 or rng == 6 or rng == 7 or rng == 8 or rng == 9:  # role

            role_rng = random.randint(1,2)

            tricked_r = [f"You were unlucky and got tricked! But hey, at least you got the {tricked.mention} role!", f"You got tricked and the {tricked.mention} role!", f"You asked for a treat... but got the {tricked.mention} role instead.", f"You were caught trying to steal candy and got the {tricked.mention} role instead!"]
            ran_tricked = random.choice(tricked_r)
            treated_r = [f"You were lucky and got candy! One of them was the {treated.mention} role!", f"You got loads of candy and the {treated.mention} role!", f"You got chocolate and the {treated.mention} role!"]
            ran_treated = random.choice(treated_r)


            if role_rng == 1:   # tricked
                await ctx.author.add_roles(tricked)
                if treated in ctx.author.roles:
                    await ctx.author.remove_roles(treated)

                embed.description = ran_tricked

            else:     # treated
                await ctx.author.add_roles(treated)
                if treated in ctx.author.roles:
                    await ctx.author.remove_roles(tricked)

                embed.description = ran_treated

        elif rng == 10 or rng == 11 or rng == 12 or rng == 13 or rng == 14 or rng == 15:  # role edit

            role_rng2 = random.randint(1,2)

            if role_rng2 == 1:  # tricked
                await tricked.edit(color=discord.Color.from_str(clr))
                embed.description = f"Changed the color of {tricked.mention} to {clr}!"

            else:   # treated
                await treated.edit(color=discord.Color.from_str(clr))
                embed.description = f"Changed the color of {treated.mention} to {clr}!"
        
        elif rng == 16 or rng == 17 or rng == 18 or rng == 19 or rng == 20:  # nicks

            nicks = ["Spoopy", "Spooky", "Scary", "Fearful", "Wicked", "Evil", "Ghostly", "Fearsome", "Haunted", "Menacing", "Frightened", "Dreadful"]
            nick = random.choice(nicks)

            try:
                new_nick = await ctx.author.edit(nick=f"{nick} {ctx.author.name}", reason="Trick or Treat!")
                embed.description = f"AHA! I changed your nickname to {new_nick}!"
            except:
                embed.description = "Boo! <a:ghostie:1031911081288933466>"

        else:   # random fact

            responses = [f"Happy Halloween from {ctx.guild.name}!", "Boo!", "Did you know \"Jack o'lantern\" comes from the Irish legend of Stingy Jack? 🎃", "Did you know candy corn was originally called Chicken Feed? 🍬", "Did you know the most lit jack o'lanterns on display is 30,581!", "Did you know halloween dates back more than 2,000 years?", "Did you know Halloween is the second largest commercial holiday in the world?", "Did you know some shelters used to suspend black cat adoptions for Halloween?", "Did you know the word \"witch\" comes from the Old English \"Wicce\", meaning wise woman? 🧹", "Did you know people originally carved turnips instead of pumpkins?", "Did you know pumpkins are classified as a fruit instead of a vegetable?", "Did you know Trick-or-treating has existed since medieval times?", "Did you know the most common Halloween costumes for adults are cats and witches?", "Did you know the most popular costume for kids is Spiderman?" ,"Did you know the fear of Halloween is called Samhainophobia?", "Did you know Harry Houdini died on Halloween in 1926? 🧙‍♂️", "Did you know the Headless Horseman isn't linked to Halloween?", "Did you know Halloween is also known as All Hallows' Eve and All Saints Eve?", "Did you know some Halloween traditions include making a bonfire and playing divination games?", "Did you know it is believed that if a child is born on Halloween, they will be able to talk to the spirits?", "Did you know China holds Halloween festivals by lighting dragon-shaped lanterns?", "Did you know the night before Halloween is referred to as Mischief Night or Goosey Night?", "Did you know a full moon on Halloween night is considered rare?", "Did you know there's a ghost behind you right now?"]

            embed.description = random.choice(responses)
    
      else:
        embed = discord.Embed(color=0xf26600, title="Trick or Treat...?", description="Isn't it a bit too late for that? Maybe again next year? <a:ghost_wave:1031912745077047399>")
        embed.set_image(url="https://cdn.discordapp.com/attachments/965915830661570593/1031921939985485944/giphy.gif")

      await ctx.send(embed=embed)

      channel = await self.bot.fetch_channel(1031926058154467398)
      await channel.send(content=ctx.author.mention, embed=embed)

# ———————— CHANNELS ————————

    global staff_cat
    global pm_cat
    global mods_cat
    global admins_cat

    staff_cat = 656987401146728451
    pm_cat = 932000955581468682
    mods_cat = 959059703357390868
    admins_cat = 959063262480203836

# ———————— MODULES ————————

    class Welcomer(commands.Cog):
      def __init__(self, bot):
        self.bot = bot


    @commands.Cog.listener()
    async def on_member_join(self, member):

      channel = self.bot.get_channel(int(os.getenv("channel")))

      if not re.search("([!-~])", member.name):
        await member.edit(nick="change nickname!", reason="Automod - Unpingable Name")
        embed=discord.Embed(color=self.bot.main_color, description=f"Changed `{member.name}`'s nickname to `change nickname!` for having an unpingable name.", timestamp=discord.utils.utcnow())
        embed.set_footer(text=f"User ID: {member.id}")
        embed.set_author(name="Automod")
        await channel.send(embed=embed)
        await member.send("Hi! it seems that you have a name that isn't easily pingable, please give yourself an easy to type nickname so we can ping you if needed! Thanks!")

      if re.search("(cunt)|(blowjob)|(whore)|(wh0re)|(retard)|(cock)|(c0ck)|(orgasm)|(0rgasm)|(masturbat)|(porn)|(p0rn)|(horny)|(卍)|(🖕)|(fuck)|(slut)|(dick)", member.name):
        await member.edit(nick="change nickname!", reason="Automod - Inappropriate Name")
        embed=discord.Embed(color=self.bot.main_color, description=f"Changed `{member.name}`'s nickname to `change nickname!` for having an inappropriate name.", timestamp=discord.utils.utcnow())
        embed.set_footer(text=f"User ID: {member.id}")
        embed.set_author(name="Automod")
        await channel.send(embed=embed)
        await member.send("Your nickname was changed for containing a banned word/being inappropriate, please give yourself a nickname that follows our <#760498694323044362>.")


      member_name = member.name

        
      if re.search("[\s]", member_name) and member.guild.id == 641449164328140802:

        member_name = urllib.parse.quote(member_name)
        welc_channel = self.bot.get_channel(641449164328140806)  # change
        avatar = member.avatar.replace(static_format='png', size=1024)


        embed = discord.Embed(color=discord.Color(0xfbfbfb), description="Make sure you read our <#760498694323044362> and get some <#760500989614227496>! <:ddlcsayoricool:846778526740119625>")

        embed.set_image(url=f"https://some-random-api.ml/welcome/img/1/stars?key=693eX9zNKHuOHeqmF8TamCzlc&username={member_name}&discriminator={member.discriminator}&avatar={avatar}&type=join&guildName=%F0%9F%8C%BC%E3%83%BBkewl%20%E0%B7%86&textcolor=white&memberCount=111")

        await asyncio.sleep(60)
        await welc_channel.send(content=f"<@&788088273943658576> get over here and welcome {member.mention}! <a:imhere:807773634097709057>", embed=embed)

    async def setup(bot):
      await bot.add_cog(Welcomer(bot))



    class on_messages(commands.Cog):
      def __innit(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message):

        meow = 808786532173480036  # change
        if message.channel.id == meow and re.search("(\.png|\.jpg|\.jpeg|\.gif|\.mov|\.mp4)", message.content) and not re.search("(809487761005346866|^\?|^\!)", message.content):
            await message.publish()


        mailbox = self.bot.get_channel(646476610853273601) # change

        if message.author.bot:
            return
        if re.search("(^!help$)|(865567515900248075> help$)", message.content):
            await message.channel.send(f"{message.author.mention} You can't use that command, use `!commands` instead!")
        if re.search("(cute)", message.content):
            await message.add_reaction("<:ddlcnatsukinou:641777411578396694>")
        if re.search("(name)", message.content) and message.channel.id == 757681621171306676:
            reactions = ["<a:bearquack:807233432160829472>", "<a:bunnypet:807756848286793778>", "<:c_wowiee:834557805171834880>", "<:catblushies7:834516662140665886>", "<:catblushies:728992066125692979>", "<:catblushies10:834528743715635220>", "<:cattolove:679847609619578924>", "<a:cc_cutebongo:792523864742559794>", "<a:cc_kittenhophop:807756847821094932>", "<:cc_kittenhearts:736648341311455314>", "<a:cc_kittenchuu:801489400298995732>", "<a:cc_kittenpatpat:807411928870944808>", "<:cc_kittyblushies:774734365154344972>", "<:cc_kittyheart:732250535943733327>", "<:chibiheart:800526569969942528>", "<:chibihihi:818515382720921672>", "<:chibilove:732250382507442219>", "<:chickhearts:779846329445908480>", "<:ddlcsayoriheart:743601377942700114>", "<a:kawaiihearts:770332490065248312>", "<:pikalovechu:780159990525722624>", "<:penguinflower:847103924750254080>", "<a:sugoi:807373099242094603>", "<a:uwu_wigglewiggle:807773634097053726>", "<a:wavE:779882812887138304>", "<a:yysmiley:800460720176496690>", "<a:yy_omgomg:807756847896985612>", "<a:yycheer:834543109983174676>"]
            react = random.choice(reactions)
            await message.add_reaction(react)
        if re.search("^(?!.*(\?verify))", message.content) and message.channel.id == 950180899310428280:    # change
            await message.channel.send(f"{message.author.mention} to verify send **?verify**", delete_after=15)
        if re.search("(how)(.*)(report)", message.content):
            await message.channel.send(f"Hey {message.author.mention}! Please DM me if you're looking to report another member! <:chibilapproval:818499768149999650>")


        if message.type == discord.MessageType.premium_guild_subscription and message.channel.id == 641449164328140806: # change
            embed=discord.Embed(description=f"**・ʚ ₊˚୨ Boosting Perks!**\n\n**1 boost:**\n・A **hoisted** role all boosters get!\n・**Image/Embed** perms!\n・Perms to **post** in <#769582489421217822>!\n・**Every** color from <#760159326693752879>!\n・One **free background** for the /rank command!\n・**7k cookies** for <@493716749342998541> every week!\n\n**2 boosts:**\n・The **previous** perks!\n・**2 free levels**!\n・**Another free background** for the </rank:981143682495434775> command!\n・A **custom role** and you'll be able to **change its color**!\n\n**2 boosts for at least a month:**\n・**All The previous** perks!\n・A **role icon** for your custom role!\n・You can **promote** something in <#646476610853273601> *or* have your **Twitch/Youtube streams/videos** get automatically announced in <#769582489421217822>!", color=self.bot.main_color)
            embed.set_thumbnail(url="https://cdn.discordapp.com/emojis/818590415179218994.webp?size=96&quality=lossless")
            embed.set_footer(text="DM me to claim your perks!")
            msg = await mailbox.send(f"**{message.author.mention} Thank you for boosting {message.guild}! We now have **{message.guild.premium_subscription_count}** boosts! <a:catvibing:807759270980485139>**", embed=embed)
            await msg.add_reaction("<a:kawaiihearts:770332490065248312>")

        if re.search("(discord.gg/)", message.content) and message.channel.id == 651753340623126538: # change

            count = 0
            links = self.bot.get_channel(651753340623126538) # change

            messages = [message async for message in links.history(limit=2000)]
            for m in messages:
                if m.author == message.author:
                    count += 1


            embed=discord.Embed(color=0x2f3136, description=f"Thanks for the partnership {message.author.mention}!")
            embed.set_footer(text=f"You have posted {count} in total!")
            await message.reply(embed=embed, allowed_mentions=discord.AllowedMentions(replied_user=False))

    async def setup(bot):
      await bot.add_cog(on_messages(bot))


    class Automod(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):

      channel = self.bot.get_channel(int(os.getenv("channel")))

      embed=discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())
      embed.set_footer(text=f"User ID: {after.id}")
      embed.set_author(name="Automod")
      
      if re.search("(cunt)|(blowjob)|(whore)|(wh0re)|(retard)|(cock)|(c0ck)|(orgasm)|(0rgasm)|(masturbat)|(porn)|(p0rn)|(horny)|(卍)|(🖕)|(fuck)|(nazi)|(hitler)", str(after.nick)):
        embed.description=f"Reset `{after.name}`'s nickname for containing a banned word."
        await channel.send(embed=embed)
        await after.edit(nick=None)
        await after.send(f"Your nickname has been reset for containing a banned word, please keep in mind our <#760498694323044362> when choosing a nickname.")

      if re.search("(nigg)|(n1gg)|(fagg)|(niqqa)|(niqqer)", str(after.nick)):
        embed.description=f"Banned {after.mention} for having a nickname with a slur."
        await channel.send(embed=embed)
        await after.send(f"You were banned for having a nickname that contained a slur.\n\nAppeal Link: https://dyno.gg/form/e0ea9302")
        await after.ban(reason="Aiko Automod - Nickname with slur.", delete_message_days=1)

      if re.search("(gg/)", str(after.nick)) and not re.search("(kewl)", str(after.nick)):
        embed.description=f"Banned {after.mention} for having a nickname with an invite."
        await channel.send(embed=embed)
        await after.send(f"You were banned for having a server link invite in your nickname.\n\nAppeal Link: https://dyno.gg/form/e0ea9302")
        await after.ban(reason="Aiko Automod - Invite in nickname.", delete_message_days=1)


    async def setup(bot):
      await bot.add_cog(Automod(bot))


    class Buttons(discord.ui.View):
      def __init__(self, *, timeout=180):
        super().__init__(timeout=timeout)
      
      @discord.ui.button(label="Button",style=discord.ButtonStyle.gray)
      async def blurple_button(self,interaction:discord.Interaction,button:discord.ui.Button):
        await interaction.response.edit_message(content=f"This is an edited button response!",view=self)

    class test(commands.Cog):
      def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @commands.command(hidden=True)
    @commands.is_owner()
    async def button(self, ctx):
        await ctx.send("This message has buttons!",view=Buttons())



    class cmds(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command(aliases=["cmd"])
    @checks.has_permissions(PermissionLevel.REGULAR)
    @trigger_typing
    async def commands(self, ctx):

      embed = discord.Embed(color=self.bot.main_color, timestamp=discord.utils.utcnow())
      embed.set_footer(text=f"Requested by {ctx.author}")
      embed.set_author(name="Aiko Commands!", icon_url=ctx.bot.user.avatar.url)

      admin = discord.utils.get(ctx.author.roles, id=704792380624076820)
      mod = discord.utils.get(ctx.author.roles, id=642122688491421696)
      member = discord.utils.get(ctx.author.roles, id=648641822431903784)
      pm = discord.utils.get(ctx.author.roles, id=751470169448120422)

      prefix = "!"
      
      if member in ctx.author.roles:
        embed.add_field(name="Normal Commands", value=f"**{prefix}ping** → Check Aiko's ping.\n**{prefix}about** → See some general info about Aiko.\n**{prefix}avatar** → Get a user's avatar (they don't need to be in the server!).\n**{prefix}banner** → Get a user's banner (they don't need to be in the server!).\n**{prefix}roleinfo** → Get get info about a role.\n**{prefix}serverinfo** → Get info about the server.\n**{prefix}flip** → Flip a coin.\n**{prefix}roast** → Roast someone (or yourself)!\n**{prefix}roll** → Roll a dice!\n**{prefix}choose** [options...] → Have Aiko choose between things for you!\n**{prefix}wordle** → Play a round of Wordle with Aiko!\n**{prefix}mycolor** → Change the color of your custom role.", inline=False)


      if mod in ctx.author.roles and (ctx.channel.category.id == staff_cat or ctx.channel.category.id == pm_cat or ctx.channel.category.id == mods_cat or ctx.channel.category.id == admins_cat) or (admin in ctx.author.roles and (re.search("(all$)", ctx.message.content) or re.search("(mod$)", ctx.message.content))):
        embed.add_field(name="Mod Commands", value=f"**{prefix}say** [your message] → Sends your message.\n**{prefix}s** → See every available snippet.\n**{prefix}notify** → Pings you when the user sends their next message.\n**{prefix}closing** → Closes the thread.\n**{prefix}new** [user] → Opens a new thread.\n**{prefix}link** → Sends the link of the current thread.\n**{prefix}logs** [user] → Checks a user's previous thread logs.\n**{prefix}block** [user] [reason] → Blocks a user.\n**{prefix}unblock** [user] → Unblocks a user.\n**{prefix}blocked** → Displays every blocked user.\n**{prefix}inv** [invite link] → Gets info about an invite.\n**{prefix}mute** [user] [limit] [reason] → Mutes a user (only use if Dyno is offline).\n**{prefix}unmute** [user] → Unmutes a user.\n**{prefix}purge** [limit] → Purges a number of messages.\n**{prefix}fixnames** → Looks for members with unpingable names and changes their nickname.", inline=False)


      if pm in ctx.author.roles and (ctx.channel.category.id == staff_cat or ctx.channel.category.id == pm_cat or ctx.channel.category.id == mods_cat or ctx.channel.category.id == admins_cat) or (admin in ctx.author.roles and (re.search("(all$)", ctx.message.content) or re.search("(pm$)", ctx.message.content))):
        embed.add_field(name="PM Commands", value=f"**{prefix}say** [your message] → Sends your message.\n**{prefix}edit** → Edit one of the messages you sent.\n**{prefix}delete** → Delete one of the messages you sent.\n**{prefix}notify** → Pings you when the user sends their next message.\n**{prefix}closing** → Closes the thread.\n**!!ad** → Sends our server's ad.\n**{prefix}inv** [invite link] → Gets info about an invite.\n**{prefix}pm** → Shows you how many partnerships you or another PM has posted.", inline=False)


      if admin in ctx.author.roles and (ctx.channel.category.id == staff_cat or ctx.channel.category.id == pm_cat or ctx.channel.category.id == mods_cat or ctx.channel.category.id == admins_cat) or (admin in ctx.author.roles and (re.search("(all$)", ctx.message.content) or re.search("(admin$)", ctx.message.content))):
        embed.add_field(name="Admin Commands", value=f"**{prefix}admin-move** → Moves the thread to the Admin category.\n**{prefix}admin-close** → Closes the thread.\n**{prefix}enable** → Opens Aiko's DMs.\n**{prefix}disable** → Closes Aiko's DMs.\n**{prefix}isenable** → Checks the status of Aiko's DMs.\n**{prefix}echo** [channel] [message] → Sends a message in a channel.\n**{prefix}webhook** [message] → Send a webhook through Aiko.\n**{prefix}ban** [user(s)] → Bans a user or multiple users.", inline=False)


      await ctx.reply(embed=embed)

    async def setup(bot):
      await bot.add_cog(cmds(bot))

async def setup(bot):
    await bot.add_cog(Modmail(bot))

