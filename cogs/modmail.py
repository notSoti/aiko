import asyncio
import re
import os
import urllib.parse
import random_word
from datetime import datetime
from itertools import zip_longest
from typing import Optional, Union
import typing
from types import SimpleNamespace
import sys
import traceback
from replit import db
from os import system

import discord
from discord.ext import commands, tasks
from discord.ext.commands.cooldowns import BucketType
from discord.role import Role
from discord.utils import escape_markdown

from dateutil import parser
from natural.date import duration

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
            val = self.bot.snippets.get(name)
            if val is None:
                embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
            else:
                embed = discord.Embed(
                    title=f'Snippet - "{name}":', description=val, color=self.bot.main_color
                )
            return await ctx.send(embed=embed)

        if not self.bot.snippets:
            embed = discord.Embed(
                color=self.bot.error_color, description="You dont have any snippets at the moment."
            )
            embed.set_footer(text=f'Check "{self.bot.prefix}help snippet add" to add a snippet.')
            embed.set_author(name="Snippets", icon_url=ctx.guild.icon_url)
            return await ctx.send(embed=embed)

        embeds = []

        for i, names in enumerate(zip_longest(*(iter(sorted(self.bot.snippets)),) * 15)):
            description = format_description(i, names)
            embed = discord.Embed(color=self.bot.main_color, description=description)
            embed.set_author(name="Snippets", icon_url=ctx.guild.icon_url)
            embeds.append(embed)

        session = EmbedPaginatorSession(ctx, *embeds)
        await session.run()

    @snippet.command(name="raw")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_raw(self, ctx, *, name: str.lower):
        """
        View the raw content of a snippet.
        """
        val = self.bot.snippets.get(name)
        if val is None:
            embed = create_not_found_embed(name, self.bot.snippets.keys(), "Snippet")
        else:
            val = truncate(escape_code_block(val), 2048 - 7)
            embed = discord.Embed(
                title=f'Raw snippet - "{name}":',
                description=f"```\n{val}```",
                color=self.bot.main_color,
            )

        return await ctx.send(embed=embed)

    @snippet.command(name="add")
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_add(self, ctx, name: str.lower, *, value: commands.clean_content):
        """
        Add a snippet.

        Simply to add a snippet, do: ```
        {prefix}snippet add hey henlo there :)
        ```
        then when you type `{prefix}hey`, "henlo there :)" will get sent to the recipient.

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

    @snippet.command(name="remove", aliases=["del", "delete"])
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    async def snippet_remove(self, ctx, *, name: str.lower):
        """Remove a snippet."""

        if name in self.bot.snippets:
            embed = discord.Embed(
                title="Removed snippet",
                color=self.bot.main_color,
                description=f"Snippet `{name}` is now deleted.",
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
                msg = f"{mention}"
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
            description=f"This thread will close {silent}in {human_delta}.",
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
    async def close(self, ctx, *, after: UserFriendlyTime = None):
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

        now = datetime.utcnow()

        close_after = (after.dt - now).total_seconds() if after else 0
        message = after.arg if after else None
        silent = str(message).lower() in {"silent", "silently"}
        cancel = str(message).lower() == "cancel"

        if cancel:

            if thread.close_task is not None or thread.auto_close_task is not None:
                await thread.cancel_closure(all=True)
                embed = discord.Embed(
                    color=self.bot.error_color, description="Scheduled close has been cancelled."
                )
            else:
                embed = discord.Embed(
                    color=self.bot.error_color,
                    description="This thread has not already been scheduled to close.",
                )

            return await ctx.send(embed=embed)

        if after and after.dt > now:
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
        await ctx.send(f"`[Thread]({log_link})`")

    def format_log_embeds(self, logs, avatar_url):
        embeds = []
        logs = tuple(logs)
        title = f"Total Results Found ({len(logs)})"

        for entry in logs:
            created_at = parser.parse(entry["created_at"])

            prefix = self.bot.config["log_url_prefix"].strip("/")
            if prefix == "NONE":
                prefix = ""
            log_url = (
                f"{self.bot.config['log_url'].strip('/')}{'/' + prefix if prefix else ''}/{entry['key']}"
            )

            username = entry["recipient"]["name"] + "#"
            username += entry["recipient"]["discriminator"]

            embed = discord.Embed(color=self.bot.main_color, timestamp=created_at)
            embed.set_author(name=f"{title} - {username}", icon_url=avatar_url, url=log_url)
            embed.url = log_url
            embed.add_field(name="Created", value=duration(created_at, now=datetime.utcnow()))
            closer = entry.get("closer")
            if closer is None:
                closer_msg = "Unknown"
            else:
                closer_msg = f"<@{closer['id']}>"
            embed.add_field(name="Closed By", value=closer_msg)

            if entry["recipient"]["id"] != entry["creator"]["id"]:
                embed.add_field(name="Created by", value=f"<@{entry['creator']['id']}>")

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
    @commands.cooldown(1, 120, BucketType.channel)
    async def title(self, ctx, *, name: str):
        """Sets title for a thread"""
        await ctx.thread.set_title(name)
        sent_emoji, _ = await self.bot.retrieve_emoji()
        await ctx.message.pin()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 30, BucketType.channel)
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
                em.timestamp = datetime.utcnow()
            em.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar_url)
            for u in users:
                await u.send(embed=em)

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
                em.timestamp = datetime.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].avatar_url)

            for i in ctx.thread.recipients:
                if i not in users:
                    await i.send(embed=em)

        await ctx.thread.add_users(users)
        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 45, BucketType.channel)
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
                em.timestamp = datetime.utcnow()
            em.set_footer(text=str(ctx.author), icon_url=ctx.author.avatar_url)
            for u in users:
                await u.send(embed=em)

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
                em.timestamp = datetime.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].avatar_url)

            for i in ctx.thread.recipients:
                if i not in users:
                    await i.send(embed=em)

        await ctx.thread.remove_users(users)
        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 30, BucketType.channel)
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

        if not silent:
            em = discord.Embed(
                title=self.bot.config["private_added_to_group_title"],
                description=self.bot.config["private_added_to_group_description_anon"],
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = datetime.utcnow()

            tag = self.bot.config["mod_tag"]
            if tag is None:
                tag = str(get_top_hoisted_role(ctx.author))
            name = self.bot.config["anon_username"]
            if name is None:
                name = tag
            avatar_url = self.bot.config["anon_avatar_url"]
            if avatar_url is None:
                avatar_url = self.bot.guild.icon_url
            em.set_footer(text=name, icon_url=avatar_url)

            for u in users:
                await u.send(embed=em)

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
                em.timestamp = datetime.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].avatar_url)

            for i in ctx.thread.recipients:
                if i not in users:
                    await i.send(embed=em)

        await ctx.thread.add_users(users)
        sent_emoji, _ = await self.bot.retrieve_emoji()
        await self.bot.add_reaction(ctx.message, sent_emoji)

    @commands.command(usage="<users_or_roles...> [options]", cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    @commands.cooldown(1, 45, BucketType.channel)
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

        if not silent:
            em = discord.Embed(
                title=self.bot.config["private_removed_from_group_title"],
                description=self.bot.config["private_removed_from_group_description_anon"],
                color=self.bot.main_color,
            )
            if self.bot.config["show_timestamp"]:
                em.timestamp = datetime.utcnow()

            tag = self.bot.config["mod_tag"]
            if tag is None:
                tag = str(get_top_hoisted_role(ctx.author))
            name = self.bot.config["anon_username"]
            if name is None:
                name = tag
            avatar_url = self.bot.config["anon_avatar_url"]
            if avatar_url is None:
                avatar_url = self.bot.guild.icon_url
            em.set_footer(text=name, icon_url=avatar_url)

            for u in users:
                await u.send(embed=em)

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
                em.timestamp = datetime.utcnow()
            em.set_footer(text=f"{users[0]}", icon_url=users[0].avatar_url)

            for i in ctx.thread.recipients:
                if i not in users:
                    await i.send(embed=em)

        await ctx.thread.remove_users(users)
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

        await ctx.trigger_typing()

        if not user:
            thread = ctx.thread
            if not thread:
                raise commands.MissingRequiredArgument(SimpleNamespace(name="member"))
            user = thread.recipient or await self.bot.fetch_user(thread.id)

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
        embeds = self.format_log_embeds(entries, avatar_url=self.bot.guild.icon_url)

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

        embeds = self.format_log_embeds(entries, avatar_url=self.bot.guild.icon_url)

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

        await ctx.trigger_typing()

        entries = await self.bot.api.search_by_text(query, limit)

        embeds = self.format_log_embeds(entries, avatar_url=self.bot.guild.icon_url)

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
                    description="Cannot find a message to edit. Plain messages are not supported.",
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
        users: commands.Greedy[Union[discord.Member, discord.User, discord.Role]],
        *,
        category: Union[SimilarCategoryConverter, str] = None,
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
        silent = False
        if isinstance(category, str):
            if "silent" in category or "silently" in category:
                silent = True
                category = category.strip("silently").strip("silent").strip()
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
                em.timestamp = datetime.utcnow()
            em.set_footer(text=f"{creator}", icon_url=creator.avatar_url)

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

        embeds = [discord.Embed(title="Blocked Users", color=self.bot.main_color, description="")]

        roles = []
        users = []
        now = ctx.message.created_at

        blocked_users = list(self.bot.blocked_users.items())
        for id_, reason in blocked_users:
            # parse "reason" and check if block is expired
            # etc "blah blah blah... until 2019-10-14T21:12:45.559948."
            end_time = re.search(r"until ([^`]+?)\.$", reason)
            if end_time is None:
                # backwards compat
                end_time = re.search(r"%([^%]+?)%", reason)
                if end_time is not None:
                    logger.warning(
                        r"Deprecated time message for user %s, block and unblock again to update.",
                        id_,
                    )

            if end_time is not None:
                after = (datetime.fromisoformat(end_time.group(1)) - now).total_seconds()
                if after <= 0:
                    # No longer blocked
                    self.bot.blocked_users.pop(str(id_))
                    logger.debug("No longer blocked, user %s.", id_)
                    continue

            user = self.bot.get_user(int(id_))
            if user:
                users.append((user.mention, reason))
            else:
                try:
                    user = await self.bot.fetch_user(id_)
                    users.append((user.mention, reason))
                except discord.NotFound:
                    users.append((id_, reason))

        blocked_roles = list(self.bot.blocked_roles.items())
        for id_, reason in blocked_roles:
            # parse "reason" and check if block is expired
            # etc "blah blah blah... until 2019-10-14T21:12:45.559948."
            end_time = re.search(r"until ([^`]+?)\.$", reason)
            if end_time is None:
                # backwards compat
                end_time = re.search(r"%([^%]+?)%", reason)
                if end_time is not None:
                    logger.warning(
                        r"Deprecated time message for role %s, block and unblock again to update.",
                        id_,
                    )

            if end_time is not None:
                after = (datetime.fromisoformat(end_time.group(1)) - now).total_seconds()
                if after <= 0:
                    # No longer blocked
                    self.bot.blocked_roles.pop(str(id_))
                    logger.debug("No longer blocked, role %s.", id_)
                    continue

            role = self.bot.guild.get_role(int(id_))
            if role:
                roles.append((role.mention, reason))

        if users:
            embed = embeds[0]

            for mention, reason in users:
                line = mention + f" - {reason or 'No Reason Provided'}\n"
                if len(embed.description) + len(line) > 2048:
                    embed = discord.Embed(
                        title="Blocked Users (Continued)",
                        color=self.bot.main_color,
                        description=line,
                    )
                    embeds.append(embed)
                else:
                    embed.description += line
        else:
            embeds[0].description = "Currently there are no blocked users."

        embeds.append(discord.Embed(title="Blocked Roles", color=self.bot.main_color, description=""))

        if roles:
            embed = embeds[-1]

            for mention, reason in roles:
                line = mention + f" - {reason or 'No Reason Provided'}\n"
                if len(embed.description) + len(line) > 2048:
                    embed = discord.Embed(
                        title="Blocked Roles (Continued)",
                        color=self.bot.main_color,
                        description=line,
                    )
                    embeds.append(embed)
                else:
                    embed.description += line
        else:
            embeds[-1].description = "Currently there are no blocked roles."

        session = EmbedPaginatorSession(ctx, *embeds)

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
                reason += f" for `{after.arg}`"
            if after.dt > after.now:
                reason += f" until {after.dt.isoformat()}"

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
                    description="Cannot find a message to delete. Plain messages are not supported.",
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
                user_id = match_user_id(message.embeds[0].footer.text)
                other_recipients = match_other_recipients(ctx.channel.topic)
                for n, uid in enumerate(other_recipients):
                    other_recipients[n] = self.bot.get_user(uid) or await self.bot.fetch_user(uid)

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
                    other_recipients[n] = self.bot.get_user(uid) or await self.bot.fetch_user(uid)

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
      r = random_word.RandomWords()
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
		
    def setup(bot):
	    bot.add_cog(ThreadID(bot))


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
            embed = discord.Embed(color=self.defaultColor, timestamp=datetime.utcnow())
            if not isinstance(member, (discord.User, discord.Member)):
                member = await MemberOrID.convert(self, ctx, member)
            try:
                await member.ban(delete_message_days=days, reason=f"{reason if reason else None}")
                banned += 1
                embed.set_author(name=ctx.author.name, icon_url=ctx.author.avatar_url)
                embed.add_field(name="User", value=f"{member.mention} | {member}", inline=False)
                embed.add_field(name="Moderator", value=f"{ctx.author.mention} | ID {ctx.author.id}", inline=False)
                embed.add_field(name="Reason", value=reason, inline=False)
                embed.set_footer(text=f"User ID: {member.id}")

            except discord.Forbidden:
                embed.set_author(name=ctx.author.name, icon_url=ctx.author.avatar_url)
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


    def setup(bot):
      bot.add_cog(Moderation(bot))



    class TimeConverter(commands.Converter):
      async def convert(self, ctx, argument):
          time_dict = {"h":3600, "m":60, "d":86400}
          time_regex = re.compile("(?:(\d{1,5})(h|m|d))+?")
          args = argument.lower()
          matches = re.findall(time_regex, args)
          time = 0


          for v, k in matches:
              try:
                  time += time_dict[k]*float(v)
              except KeyError:
                  raise commands.BadArgument("{} is an invalid time.".format(k))
              except ValueError:
                  raise commands.BadArgument("{} is not a number.".format(v))
          return time

    class MuteCog(commands.Cog):
      def __init__(self, bot):
          self.bot = bot


    @commands.command()
    @checks.has_permissions(PermissionLevel.MODERATOR)
    async def mute(self, ctx, member:discord.Member, *, time:TimeConverter = None, reason=None):
        """
        {prefix}mute [user] [limit] [reason]
        """

        channel = self.bot.get_channel(int(os.getenv("channel")))
        role = discord.utils.get(ctx.guild.roles, name="Muted")

        await member.add_roles(role, reason=reason)
        await ctx.send(f"Muted {member} for {time}.")
        embed = discord.Embed(title="Mute", color=self.bot.main_color, timestamp = datetime.utcnow())
        embed.add_field(name="Moderator", value=f"{ctx.author.mention}", inline=False)
        embed.add_field(name="User", value=f"{member.mention}", inline=False)
        embed.add_field(name="Duration", value=f"{time}", inline=False)
        embed.add_field(name="Reason", value=f"{reason}", inline=False)
        embed.set_footer(text=f"User ID: {member.id}")

        await channel.send(embed=embed)
        if time:
            await asyncio.sleep(time)
            await member.remove_roles(role)
            embed = discord.Embed(title="Unmute", color=self.bot.main_color, timestamp = datetime.utcnow())
            embed.add_field(name="Moderator", value="<@865567515900248075>")
            embed.add_field(name="User", value=f"{member.mention}")
            embed.set_footer(text=f"User ID: {member.id}")
            await channel.send(embed=embed)


    @commands.command()
    @checks.has_permissions(PermissionLevel.MODERATOR)
    async def unmute(self, ctx, member:discord.Member):

      channel = self.bot.get_channel(int(os.getenv("channel")))
      role = discord.utils.get(ctx.guild.roles, name="Muted")

      await member.remove_roles(role)
      embed = discord.Embed(title="Unmute", color=self.bot.main_color, timestamp = datetime.utcnow())
      embed.add_field(name="Moderator", value=f"{ctx.author.mention}")
      embed.add_field(name="User", value=f"{member.mention}")
      embed.set_footer(text=f"User ID: {member.id}")
      await channel.send(embed=embed)


    @commands.command()
    @checks.has_permissions(PermissionLevel.MODERATOR)
    @commands.cooldown(2, 240, BucketType.user)
    async def purge(self, ctx, amount: int = 1):
      """
      {prefix}purge [limit]
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
      embed = discord.Embed(color=self.bot.main_color, timestamp=datetime.utcnow())
      embed.add_field(name="Purge", value=f"{ctx.author.mention} ({ctx.author}) purged {amount} {messages} in {ctx.channel.mention}.", inline=False)
      embed.set_footer(text=f"User ID: {ctx.author.id}")

      await channel.send(embed=embed)
      

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMIN)
    async def embed(self, ctx: commands.Context):
        """
        {prefix}embed
        """

        def check(msg: discord.Message):
            return ctx.author == msg.author and ctx.channel == msg.channel


        def title_check(msg: discord.Message):
            return (
                ctx.author == msg.author
                and ctx.channel == msg.channel
                and (len(msg.content) < 256)
            )

        def description_check(msg: discord.Message):
            return (
                ctx.author == msg.author
                and ctx.channel == msg.channel
                and (len(msg.content) < 2048)
            )

        def footer_check(msg: discord.Message):
            return (
                ctx.author == msg.author
                and ctx.channel == msg.channel
                and (len(msg.content) < 2048)
            )


        def cancel_check(msg: discord.Message):
            if msg.content == "cancel" or msg.content == f"{ctx.prefix}cancel":
                return True
            else:
                return False


        await ctx.send(
            embed=await self.generate_embed("Do you want it to be an embed? `[y/n]`")
        )

        embed_res: discord.Message = await self.bot.wait_for("message", check=check)
        if cancel_check(embed_res) is True:
            await ctx.send("Cancelled.")
            return
        elif cancel_check(embed_res) is False and embed_res.content.lower() == "n":
            await ctx.send(
                embed=await self.generate_embed(
                    "Okay, let's do a no-embed announcement."
                    "\nWhat's the announcement?"
                )
            )
            announcement = await self.bot.wait_for("message", check=check)
            if cancel_check(announcement) is True:
                await ctx.send("Cancelled.")
                return
            else:
                await ctx.send(
                    embed=await self.generate_embed(
                        "To which channel should I send the announcement?"
                    )
                )
                channel: discord.Message = await self.bot.wait_for(
                    "message", check=check
                )
                if cancel_check(channel) is True:
                    await ctx.send("Cancelled!")
                    return
                else:
                    if channel.channel_mentions[0] is None:
                        await ctx.send("Cancelled as no channel was provided")
                        return
                    else:
                        await channel.channel_mentions[0].send(
                            f"{role_mention}\n{announcement.content}"
                        )
        elif cancel_check(embed_res) is False and embed_res.content.lower() == "y":
            embed = discord.Embed()
            await ctx.send(
                embed=await self.generate_embed(
                    "Should the embed have a title? `[y/n]`"
                )
            )
            t_res = await self.bot.wait_for("message", check=check)
            if cancel_check(t_res) is True:
                await ctx.send("Cancelled")
                return
            elif cancel_check(t_res) is False and t_res.content.lower() == "y":
                await ctx.send(
                    embed=await self.generate_embed(
                        "What should the title of the embed be?"
                        "\n**Must not exceed 256 characters**"
                    )
                )
                tit = await self.bot.wait_for("message", check=title_check)
                embed.title = tit.content
            await ctx.send(
                embed=await self.generate_embed(
                    "Should the embed have a description?`[y/n]`"
                )
            )
            d_res: discord.Message = await self.bot.wait_for("message", check=check)
            if cancel_check(d_res) is True:
                await ctx.send("Cancelled")
                return
            elif cancel_check(d_res) is False and d_res.content.lower() == "y":
                await ctx.send(
                    embed=await self.generate_embed(
                        "What do you want as the description for the embed?"
                        "\n**Must not exceed 2048 characters**"
                    )
                )
                des = await self.bot.wait_for("message", check=description_check)
                embed.description = des.content

            await ctx.send(
                embed=await self.generate_embed(
                    "Should the embed have a thumbnail?`[y/n]`"
                )
            )
            th_res: discord.Message = await self.bot.wait_for("message", check=check)
            if cancel_check(th_res) is True:
                await ctx.send("Cancelled")
                return
            elif cancel_check(th_res) is False and th_res.content.lower() == "y":
                await ctx.send(
                    embed=await self.generate_embed(
                        "What's the thumbnail of the embed? Enter a " "valid URL"
                    )
                )
                thu = await self.bot.wait_for("message", check=check)
                embed.set_thumbnail(url=thu.content)

            await ctx.send(
                embed=await self.generate_embed("Should the embed have a image?`[y/n]`")
            )
            i_res: discord.Message = await self.bot.wait_for("message", check=check)
            if cancel_check(i_res) is True:
                await ctx.send("Cancelled")
                return
            elif cancel_check(i_res) is False and i_res.content.lower() == "y":
                await ctx.send(
                    embed=await self.generate_embed(
                        "What's the image of the embed?"
                    )
                )
                i = await self.bot.wait_for("message", check=check)
                embed.set_image(url=i.content)

            await ctx.send(
                embed=await self.generate_embed("Will the embed have a footer?`[y/n]`")
            )
            f_res: discord.Message = await self.bot.wait_for("message", check=check)
            if cancel_check(f_res) is True:
                await ctx.send("Cancelled")
                return
            elif cancel_check(f_res) is False and f_res.content.lower() == "y":
                await ctx.send(
                    embed=await self.generate_embed(
                        "What do you want the footer of the embed to be?"
                        "\n**Must not exceed 2048 characters**"
                    )
                )
                foo = await self.bot.wait_for("message", check=footer_check)
                embed.set_footer(text=foo.content)

            await ctx.send(
                embed=await self.generate_embed(
                    "Do you want it to have a color?`[y/n]`"
                )
            )
            c_res: discord.Message = await self.bot.wait_for("message", check=check)
            if cancel_check(c_res) is True:
                await ctx.send("Cancelled.")
                return
            elif cancel_check(c_res) is False and c_res.content.lower() == "y":
                await ctx.send(
                    embed=await self.generate_embed(
                        "What color should the embed have? "
                        "Please provide a valid hex color"
                    )
                )
                colo = await self.bot.wait_for("message", check=check)
                if cancel_check(colo) is True:
                    await ctx.send("Cancelled.")
                    return
                else:
                    match = re.search(
                        r"^#(?:[0-9a-fA-F]{3}){1,2}$", colo.content
                    )  # uwu thanks stackoverflow
                    if match:
                        embed.colour = int(
                            colo.content.replace("#", "0x"), 0
                        )  # Basic Computer Science
                    else:
                        await ctx.send(
                            "Invalid hex."
                        )
                        return

            await ctx.send(
                embed=await self.generate_embed(
                    "In which channel should I send the announcement?"
                )
            )
            channel: discord.Message = await self.bot.wait_for("message", check=check)
            if cancel_check(channel) is True:
                await ctx.send("Cancelled.")
                return
            else:
                if channel.channel_mentions[0] is None:
                    await ctx.send("Cancelled as no channel was provided")
                    return
                else:
                    schan = channel.channel_mentions[0]
            await ctx.send(
                "Here is how the embed looks like: Send it? `[y/n]`", embed=embed
            )
            s_res = await self.bot.wait_for("message", check=check)
            if cancel_check(s_res) is True or s_res.content.lower() == "n":
                await ctx.send("Cancelled")
                return
            else:
                await schan.send(embed=embed)

    @staticmethod
    async def generate_embed(description: str):
        embed = discord.Embed()
        embed.colour = discord.Colour.blurple()
        embed.description = description

        return embed


    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMIN)
    async def echo(self, ctx: commands.Context, channel: discord.TextChannel, *, msg: str):
      """
      {prefix}echo [channel] [message]
      """

      await channel.send(f"{msg}")
      await ctx.message.add_reaction("<:aiko_success:965918214498443274>")
      print(f"{ctx.author} used the echo command and said: {msg}.")



    class webhooks(commands.Cog):
      def __init__(self, bot):
        self.bot = bot
        self._last_result = None

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMINISTRATOR)
    async def webhook(self, ctx, member: discord.Member, *, msg):
        """
       Make webhooks to act like making a user say something.
        """

        webhook = await ctx.channel.create_webhook(name="su")
        await webhook.send(content=msg, username=member.name, avatar_url=member.avatar_url)
        await webhook.delete()

        message = ctx.message
        message.author = member
        message.content = msg
        await self.bot.process_commands(message)
        print(f"{ctx.author} used the webhook command on {member} and said: {msg}")

    def setup(bot):
      bot.add_cog(webhooks(bot))


    class wyr(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @checks.has_permissions(PermissionLevel.MOD)
    @commands.cooldown(1, 36000, BucketType.guild)
    async def wyr(self, ctx, choice1, choice2):
      """
      A would you rather command, separate the choices with "", for example: {prefix}wyr "eat ice cream" "eat pizza"

      Template:
      <a:1whiteheart:801122446966128670> ⋆ Would you rather? ||*By [user]*||

      <a:1arrow:801122446874509352> ⋆ **Option 1**
      <a:1arrow:801122446874509352> ⋆ **Option 2**

      ⊹ ─── ⊹ ─── ⊹ ─── <@&760529762450931718> ─── ⊹ ─── ⊹ ─── ⊹
      """

      wyr_channel = self.bot.get_channel(1000806786447720548) # change
      choice1 = choice1.capitalize()
      choice2 = choice2.capitalize()
      
      await ctx.send(f"The message will look like this, send it? (yes/no)\n\n<a:1whiteheart:801122446966128670> ⋆ Would you rather? ||*By {ctx.author.mention}*||\n\n<a:1arrow:801122446874509352> ⋆ **{choice1}**\n<a:1arrow:801122446874509352> ⋆ **{choice2}**\n\n⊹ ─── ⊹ ─── ⊹ ─── **[events ping]** ─── ⊹ ─── ⊹ ─── ⊹")

      def check(m):
        return m.author == ctx.author and m.channel == ctx.channel
      
      try:
        response = await self.bot.wait_for('message', check=check, timeout=30)
      except asyncio.TimeoutError:
        await ctx.message.add_reaction("<:aiko_error:965918214171291659>")
        ctx.command.reset_cooldown(ctx)
        return

      if response.content.lower() in ("yes", "y", "<:chibilapproval:818499768149999650>", "<:ddlcsayoricool:846778526740119625>", "ofc", "ye", "yeah", "yehs", "yesh"):
        msg = await wyr_channel.send(f"<a:1whiteheart:801122446966128670> ⋆ Would you rather? ||*By {ctx.author.mention}*||\n\n<a:1arrow:801122446874509352> ⋆ **{choice1}**\n<a:1arrow:801122446874509352> ⋆ **{choice2}**\n\n⊹ ─── ⊹ ─── ⊹ ─── **<@&760529762450931718>** ─── ⊹ ─── ⊹ ─── ⊹") 
        await msg.add_reaction("<:aiko_1:965916655878291507>")
        await msg.add_reaction("<:aiko_2:965916656536789052>")
      else:
        await ctx.send("Canceled.")
        ctx.command.reset_cooldown(ctx)
        return

    def setup(bot):
      bot.add_cog(wyr(bot))


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

    def setup(bot):
      bot.add_cog(automod_cmds(bot))


    class restart(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @checks.has_permissions(PermissionLevel.OWNER)
    @commands.cooldown(1, 60, BucketType.user)
    async def restart(self, ctx):

      await ctx.channel.send("Restarting.")
      system("kill 11") 


    def setup(bot):
      bot.add_cog(restart(bot))


    class partner(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @checks.has_permissions(PermissionLevel.SUPPORTER)
    @checks.thread_only()
    async def partner(self, ctx):

      partner = discord.utils.get(ctx.guild.roles, id=741774737168007219)
      channel = self.bot.get_channel(int(os.getenv("channel")))
      member = ctx.guild.get_member(ctx.thread.id)


      embed=discord.Embed(color=self.bot.main_color, timestamp=datetime.utcnow())
      embed.add_field(name="Role Added", value=f"{ctx.thread.recipient.mention} ({ctx.thread.recipient}) was given the <@&741774737168007219> role by {ctx.author.mention} ({ctx.author}).")
      embed.set_footer(text=f"PM ID: {ctx.author.id} - User ID: {ctx.thread.recipient.id}")

      await member.add_roles(partner, reason="Partnership", atomic=True)
      await channel.send(embed=embed)
      await ctx.message.add_reaction("<:aiko_success:965918214498443274>")

    def setup(bot):
      bot.add_cog(partner(bot))



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
      message = "Every unverified member that has been in the server for more than 10h, use **!rules kick** to kick them.\n\n"


      for member in ctx.guild.members:
        if member.bot == False and role not in member.roles:

          today = datetime.now()
          delta = int(((today - member.joined_at).total_seconds())/3600)
          
          if delta >= 10:
            message += f"{member.mention} - `{delta} hours ago`\n"
      await ctx.channel.send(message)

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

          today = datetime.now()
          delta = int(((today - member.joined_at).total_seconds())/3600)

          if delta >= 10:

            await member.send(f"Didn't verify | Join again using this invite discord.gg/HWEc5bwJJC <:bearheart2:779833250649997313>")
            await member.kick(reason="Didn't verify")
            count += 1

      if count == 1:
        await ctx.channel.send(f"Kicked {count} unverified member.")
      else:
        await ctx.channel.send(f"Kicked {count} unverified member.")


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

          today = datetime.now()
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

          today = datetime.now()
          delta = int(((today - member.joined_at).total_seconds())/3600)
          
          message += f"{member.mention} - `{delta} hours ago`\n"
      await ctx.channel.send(message)


    def setup(bot):
      bot.add_cog(rules(bot))



    class customRoles(commands.Cog):
      def __init__(self, bot):
        self.bot = bot


    @commands.command(aliases=["mycolour"], cooldown_after_parsing=True)
    @checks.has_permissions(PermissionLevel.REGULAR)
    @trigger_typing
    @commands.cooldown(1, 10, BucketType.user)
    async def mycolor(self, ctx, hex):

      """
      Change the color of your custom role!
      """

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


      embed=discord.Embed(color=discord.Color.from_rgb(47, 49, 54))

      if re.search("(^#)", hex):
          hex = hex.replace("#", "0x")

      new_hex = int(hex, 16)

      if winter in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {winter.mention} role to {hex}.", inline=False)
          await winter.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif cinni in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {cinni.mention} role to {hex}.", inline=False)
          await cinni.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")
      
      elif realist in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {realist.mention} role to {hex}.", inline=False)
          await realist.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif emy in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {emy.mention} role to {hex}.", inline=False)
          await emy.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif dis in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {dis.mention} role to {hex}.", inline=False)
          await dis.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif soti in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {soti.mention} role to {hex}.", inline=False)
          await soti.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif lillie in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {lillie.mention} role to {hex}.", inline=False)
          await lillie.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif star in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {star.mention} role to {hex}.", inline=False)
          await star.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif lina in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {lina.mention} role to {hex}.", inline=False)
          await lina.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      elif vera in ctx.author.roles:
          embed.add_field(name="Color Changed", value=f"Changed the color of the {vera.mention} role to {hex}.", inline=False)
          await vera.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")
      

      elif voter in ctx.author.roles and (winter and cinni and realist and emy and dis and soti and lillie and star and lina and vera not in ctx.author.roles):
        embed.add_field(name="Color Changed", value=f"Changed the color of the {voter.mention} role to {hex}.", inline=False)
        await voter.edit(color = new_hex, reason = f"Custom role color change by {ctx.author}")

      else:
        embed.add_field(name="No custom role found!", value=f"Head to <#741835235737731083> to learn how to get a custom role!", inline=False)

      await ctx.channel.send(embed=embed)


    def setup(bot):
      bot.add_cog(customRoles(bot))



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

    global welc_state
    welc_state = "on"
    class Welcomer(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command(aliases=["welc"])
    @checks.has_permissions(PermissionLevel.ADMIN)
    @commands.cooldown(1, 7, BucketType.user)
    async def welcome(self, ctx, welc_state):
      """
      Enable or disable Aiko's Welcome module.
      {prefix}welcome on
      {prefix}welcome off
      """

      if welc_state == "off":
        await ctx.send("Disabled the Welcome module.")
        welc_state = "off"
      elif welc_state == "on":
        await ctx.send("Enabled the Welcome module.")
        welc_state = "on"

    @commands.Cog.listener()
    async def on_member_join(self, member):

      channel = self.bot.get_channel(int(os.getenv("channel")))

      if not re.search("([!-~])", member.name):
        await member.edit(nick="change nickname!", reason="Automod - Unpingable Name")
        embed=discord.Embed(color=self.bot.main_color, description=f"Changed {member.mention}'s nickname to `change nickname` for having an unpingable name.", timestamp=datetime.utcnow())
        embed.set_footer(text=f"User ID: {member.id}")
        embed.set_author(name="Automod")
        await channel.send(embed=embed)
        await member.send("Hi! it seems that you have a name that isn't easily pingable, please give yourself an easy to type nickname so we can ping you if needed! Thanks!")

      if re.search("(cunt)|(blowjob)|(whore)|(wh0re)|(retard)|(cock)|(c0ck)|(orgasm)|(0rgasm)|(masturbat)|(porn)|(p0rn)|(horny)|(卍)|(🖕)|(fuck)|(slut)|(dick)", member.name):
        await member.edit(nick="change nickname!", reason="Automod - Inappropriate Name")
        embed=discord.Embed(color=self.bot.main_color, description=f"Changed {member.mention}'s nickname to `change nickname` for having an inappropriate name.", timestamp=datetime.utcnow())
        embed.set_footer(text=f"User ID: {member.id}")
        embed.set_author(name="Automod")
        await channel.send(embed=embed)
        await member.send("Your nickname was changed for containing a banned word/being inappropriate, please give yourself a nickname that follows our <#760498694323044362>.")


      member_name = member.name

      if welc_state == "on":
        
        if re.search("[\s]", member_name):

          member_name = urllib.parse.quote(member_name)
          welc_channel = self.bot.get_channel(641449164328140806)  # change
          avatar = member.avatar_url_as(static_format='png', size=1024)


          embed = discord.Embed(color=discord.Color(0xfbfbfb), description="Make sure you read our <#760498694323044362> and get some <#760500989614227496>! <:ddlcsayoricool:846778526740119625>")

          embed.set_image(url=f"https://some-random-api.ml/welcome/img/1/stars?key=693eX9zNKHuOHeqmF8TamCzlc&username={member_name}&discriminator={member.discriminator}&avatar={avatar}&type=join&guildName=%F0%9F%8C%BC%E3%83%BBkewl%20%E0%B7%86&textcolor=white&memberCount=111")

          await asyncio.sleep(30)
          await welc_channel.send(content=f"<@&788088273943658576> get over here and welcome {member.mention}! <a:imhere:807773634097709057>", embed=embed)

    def setup(bot):
      bot.add_cog(Welcomer(bot))



    global ar_state
    ar_state="on"
    class Autoresponder(commands.Cog):
      def __init__ (self, bot):
        self.bot = bot

    @commands.command(aliases=["ar", "autoresponders"])
    @commands.cooldown(1, 7, BucketType.user)
    @checks.has_permissions(PermissionLevel.ADMIN)
    async def autoresponder(self, ctx, ar_state):
      """
      Enable or disable Aiko's Autoresponder module.
      {prefix}autoresponder on
      {prefix}autoresponder off
      """

      if ar_state == "off":
        await ctx.send("Disabled the Autoresponder module.")
        ar_state = "off"
      elif ar_state == "on":
        await ctx.send("Enabled the Autoresponder module.")
        ar_state = "on"

    def setup(bot):
      bot.add_cog(Autoresponder(bot))

    global ap_state
    ap_state = "on"
    class AutoPublish(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command(aliases=["ap"])
    @commands.cooldown(1, 7, BucketType.user)
    @checks.has_permissions(PermissionLevel.ADMIN)
    async def autopublish(self, ctx, ap_state):
      """
      Enable or disable Aiko's the Autopublish module.
      {prefix}autopublish on
      {prefix}autopublish off
      """

      if ap_state == "off":
        await ctx.send("Disabled the Autopublish module.")
        ap_state = "off"
      elif ap_state == "on":
        await ctx.send("Enabled the Autopublish module.")
        ap_state = "on"

    def setup(bot):
      bot.add_cog(AutoPublish(bot))



    class on_messages(commands.Cog):
      def __innit(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message):

      if ap_state == "on":

        meow = 808786532173480036  # change
        if message.channel.id == meow and not re.search("(809487761005346866)", message.content):
          await message.publish()

      if ar_state == "on":

        if message.author.bot:
          return
        if re.search("(^!help$)|(865567515900248075> help$)", message.content):
          await message.channel.send(f"{message.author.mention} You can't use that command, use `!commands` instead!")
        if re.search("(cute)", message.content):
          await message.add_reaction("<:ddlcnatsukinou:641777411578396694>")
        if re.search("^(?!.*(\?verify))", message.content) and message.channel.id == 950180899310428280:
          await message.channel.send(f"{message.author.mention} to verify send **?verify**", delete_after=15)
        if re.search("(865567515900248075>)", message.content):
          await message.add_reaction("<:aiko:965918603566284820>")
        if re.search("(how)(.*)(report)", message.content):
          await message.channel.send(f"Hey {message.author.mention}! Please DM me if you're looking to report another member! <:chibilapproval:818499768149999650>")
        if re.search("(just boosted the server!$)", message.content) and message.channel.id == 641449164328140806:
          embed=discord.Embed(description=f"**Thank you for boosting {message.guild}! Make sure to check out <#741835235737731083> to see the perks you can get!** <:ddlcsayoriheart:743601377942700114>", color=self.bot.main_color)
          embed.set_thumbnail(url="https://cdn.discordapp.com/emojis/818590415179218994.webp?size=96&quality=lossless")
          embed.set_footer(text="DM me to claim your perks!")
          await message.channel.send(f"{message.author.mention} just boosted us! <a:catvibing:807759270980485139>", embed=embed)
        if re.search("(discord.gg/)", message.content) and message.channel.id == 651753340623126538:
          embed=discord.Embed(color=discord.Color.from_rgb(255, 255, 255), description=f"Thanks for the partnership {message.author.mention}!")
          await message.channel.send(embed=embed)

    def setup(bot):
      bot.add_cog(on_messages(bot))


    class Automod(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_member_update(self, before: discord.Member, after: discord.Member):

      channel = self.bot.get_channel(int(os.getenv("channel")))

      embed=discord.Embed(color=self.bot.main_color, timestamp=datetime.utcnow())
      embed.set_footer(text=f"User ID: {after.id}")
      embed.set_author(name="Automod")
      
      if re.search("(cunt)|(blowjob)|(whore)|(wh0re)|(retard)|(cock)|(c0ck)|(orgasm)|(0rgasm)|(masturbat)|(porn)|(p0rn)|(horny)|(卍)|(🖕)|(fuck)|(nazi)|(hitler)", str(after.nick)):
        embed.description=f"Reset {after.mention}'s nickname for containing a banned word."
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


    def setup(bot):
      bot.add_cog(Automod(bot))


    class modules(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @checks.has_permissions(PermissionLevel.ADMIN)
    async def modules(self, ctx):
      prefix = "!"
      embed = discord.Embed(

        set_author="Modules",
        color=self.bot.main_color
      )

      embed.add_field(name="Welcome", value=f"{welc_state}", inline=False)
      embed.add_field(name="Autopublish", value=f"{ap_state}", inline=False)
      embed.add_field(name="Autoresponder", value=f"{ar_state}", inline=False)
      embed.add_field(name="Automod", value=f"`NaN`", inline=False)
      embed.set_footer(text=f"To enable/disable a specific module do {prefix}module_name on/off.")
      embed.set_author(name="Modules")

      await ctx.send(embed=embed)

    def setup(bot):
      bot.add_cog(modules(bot))


    class cmds(commands.Cog):
      def __init__(self, bot):
        self.bot = bot

    @commands.command(aliases=["cmd"])
    @checks.has_permissions(PermissionLevel.REGULAR)
    @trigger_typing
    async def commands(self, ctx):

      embed = discord.Embed(
        set_author="Aiko Commands!", 
        icon_url="https://cdn.discordapp.com/avatars/865567515900248075/dec4082f6e9a227908637bf834169649.png?size=4096",
        color=self.bot.main_color,
        set_footer=f"Requested by {ctx.author}",
        timestamp=datetime.utcnow()
      )

      admin = discord.utils.get(ctx.author.roles, id=704792380624076820)
      mod = discord.utils.get(ctx.author.roles, id=642122688491421696)
      member = discord.utils.get(ctx.author.roles, id=648641822431903784)
      pm = discord.utils.get(ctx.author.roles, id=751470169448120422)

      prefix = "!"
      
      if member in ctx.author.roles:
        embed.add_field(name="Normal Commands", value=f"**{prefix}ping** → Check Aiko's ping.\n**{prefix}about** → See some general info about Aiko.\n**{prefix}avatar** → Get a user's avatar.\n**{prefix}emoji** → Get info about an emoji.\n**{prefix}roleinfo** → Get get info about a role.\n**{prefix}serverinfo** → Get info about the server.\n**{prefix}userstatus** → Get the status of a member.\n**{prefix}rps** → Play rock, paper, scissors!\n**{prefix}flip** → Flip a coin.\n**{prefix}meme** → Sends a meme!\n**{prefix}roast** → Roast someone!\n**{prefix}roll** → Roll a dice!\n**{prefix}8ball** [question] → Ask the 8ball a question!\n**{prefix}choose** [\"option 1\"] [\"option 2\"] → Have Aiko choose between things for you!\n**{prefix}wordle** → Play a round of Wordle with Aiko!\n**{prefix}mycolor** → Change the color of your custom role.", inline=False)


      if mod in ctx.author.roles and (ctx.channel.category.id == staff_cat or ctx.channel.category.id == pm_cat or ctx.channel.category.id == mods_cat or ctx.channel.category.id == admins_cat):
        embed.add_field(name="Mod Commands", value=f"**{prefix}say** [your message] → Sends your message.\n**{prefix}notify** → Pings you when the user sends their next message.\n**{prefix}closing** → Closes the thread.\n**{prefix}close silently** → Immediately closes the thread silently (always use !closing first).\n**{prefix}new** [user] silently → Opens a new thread.\n**{prefix}link** → Sends the link of the current thread.\n**{prefix}logs** [user] → Checks a user's previous thread logs.\n**{prefix}block** [user] [reason] → Blocks a user.\n**{prefix}unblock** [user] → Unblocks a user.\n**{prefix}blocked** → Displays every blocked user.\n**{prefix}inv** [invite] → Gets info about an invite.\n**{prefix}mute** [user] [limit] [reason] → Mutes a user (only use if Dyno is offline).\n**{prefix}unmute** [user] → Unmutes a user.\n**{prefix}purge** [limit] → Purges a number of messages.\n**{prefix}fixnames** → Looks for members with unpingable names and changes their nickname.", inline=False)


      if pm in ctx.author.roles and (ctx.channel.category.id == staff_cat or ctx.channel.category.id == pm_cat or ctx.channel.category.id == mods_cat or ctx.channel.category.id == admins_cat):
        embed.add_field(name="PM Commands", value=f"**{prefix}say** [your message] → Sends your message.\n**{prefix}notify** → Pings you when the user sends their next message.\n**{prefix}pm-close** → Closes the thread.\n**!!ad** → Sends our server's ad.\n**{prefix}partner → Gives the user the partner role (only usable in threads).**\n**{prefix}inv** [invite] → Gets info about an invite.", inline=False)


      if admin in ctx.author.roles and (ctx.channel.category.id == staff_cat or ctx.channel.category.id == pm_cat or ctx.channel.category.id == mods_cat or ctx.channel.category.id == admins_cat):
        embed.add_field(name="Admin Commands", value=f"**{prefix}admin-move** → Moves the thread to the Admin category.\n**{prefix}admin-close** → Closes the thread.\n**{prefix}enable** → Opens Aiko's DMs.\n**{prefix}disable** → Closes Aiko's DMs.\n**{prefix}isenable** → Checks the status of Aiko's DMs.\n**{prefix}echo** [channel] [message] → Sends a message in a channel.\n**{prefix}embed** → Creates an embed.\n**{prefix}webhook** [user] [message] → Create a webhook disguised as a user.\n**{prefix}ban** [user(s)] → Bans a user or multiple users.\n**{prefix}modules** → See every module and its status.", inline=False)
        

        embed.set_author(name="Aiko Commands!", icon_url="https://cdn.discordapp.com/avatars/865567515900248075/dec4082f6e9a227908637bf834169649.png?size=4096"),
        color=self.bot.main_color,
        embed.set_footer(text=f"Requested by {ctx.author}")


      return await ctx.send(embed=embed)

    def setup(bot):
      bot.add_cog(cmds(bot))

def setup(bot):
    bot.add_cog(Modmail(bot))

