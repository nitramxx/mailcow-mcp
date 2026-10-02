# Tools

Every tool acts as the signed-in mailbox only. Reading never marks mail as read. Nothing deletes
mail permanently except `delete_draft` (drafts only) and `delete_from_quarantine`.

Email content in tool results is wrapped and labelled as untrusted (see
[security.md](security.md)).

With `SENDING=drafts_only` the server doesn't offer `send_email` and `send_draft`: messages are
saved with `save_draft`, and you send them from your mail app.

| Tool | Mode | Changes something |
|---|---|---|
| [send_email](#send_email) | both | sends |
| [save_draft](#save_draft) | both | yes |
| [send_draft](#send_draft) | both | sends |
| [delete_draft](#delete_draft) | both | yes |
| [list_folders](#list_folders) | both | |
| [list_messages](#list_messages) | both | |
| [search_messages](#search_messages) | both | |
| [read_message](#read_message) | both | |
| [get_attachment](#get_attachment) | both | |
| [find_replies](#find_replies) | both | |
| [get_thread](#get_thread) | both | |
| [mark_messages](#mark_messages) | both | flags |
| [move_messages](#move_messages) | both | moves |
| [list_spam](#list_spam) | both | |
| [rescue_from_junk](#rescue_from_junk) | both | moves |
| [release_from_quarantine](#release_from_quarantine) | mailcow | delivers |
| [delete_from_quarantine](#delete_from_quarantine) | mailcow | deletes |
| [delivery_status](#delivery_status) | mailcow | |
| [my_addresses](#my_addresses) | mailcow | |
| [find_contacts](#find_contacts) | mailcow; generic with `CARDDAV_URL` | |

## Sending and drafts

### send_email

Sends an email. Fields: `to`, `cc`, `bcc` (each `name@example.com` or `Name <name@example.com>`,
at most 50 in total), `subject`, and either `body_markdown` (sent as HTML with a plain-text
alternative) or `body_text`. Optional: `from_name`, `from_address` (one of your addresses or
aliases; mailcow's sender rules decide), `in_reply_to` (a Message-ID: threads the reply with
`In-Reply-To` and `References`), `attachments`. A copy is saved to Sent. Returns the new
Message-ID.

Attachments (up to 10, `MAX_MESSAGE_MB` in total), each one of:

- `{"filename", "content_base64", "mime_type"}`: a file the client supplies;
- `{"from_message": {"folder", "uid", "part_id"}}`: an attachment of a message in the mailbox
  (`part_id` from `read_message`);
- `{"render_pdf": {"filename", "markdown", "title"}}`: a PDF the server renders from Markdown.

Executables are refused, and declared types must match the content.

> "Send Jana (jana@firma.cz) a short thank-you for yesterday's meeting, in Czech."
>
> "Read the Google Doc *Offer 2026*, then send it to test@example.com as an attached PDF."

### save_draft

Same fields as `send_email`; stores the message in Drafts instead of sending. Returns its UID.

> "Draft a reply to Petr's last email declining politely, but don't send it."

### send_draft

Sends a draft (by UID) exactly as it is stored now (you may have edited it in your mail app),
files it in Sent and removes it from Drafts. If no copy could be saved to Sent, the draft is kept
(the result says so), so the message still exists in your mailbox.

> "Send the draft to Petr that I just reviewed."

### delete_draft

Deletes one draft (Drafts folder only).

## Reading and follow-up

### list_folders

Folders with their role (inbox, sent, drafts, junk, trash, archive), message and unread counts.

> "How many unread messages do I have, and in which folders?"

### list_messages

Newest messages in a folder (default INBOX): sender, recipients, subject, date, flags. Options:
`limit` (≤ 50), `unread_only`, `since` (YYYY-MM-DD).

> "What came in today?"

### search_messages

Search a folder by `sender`, `to`, `subject`, `text`, `since`, `before`.

> "Find the invoice from Alza from March."

### read_message

One message: headers, the text body (HTML is converted to text), and attachments with their
`part_id`.

### get_attachment

The text of PDF, DOCX and text attachments, images as images, metadata for anything else (up to
5 MB and 50,000 characters).

> "Summarise the PDF attached to the last email from the accountant."

### find_replies

Replies to a message you sent (by Message-ID), found by `In-Reply-To`/`References` in INBOX and,
by default, Junk. On mailcow it also lists quarantined messages from the original recipients after
the original was sent, marked `possible_reply` (quarantine keeps no threading headers). Each result
says where it was found.

> "Did anyone reply to the offer I sent on Monday? Check spam too."

### get_thread

The whole conversation around a message, oldest first, across INBOX, Sent, Junk and Archive:
the newest 30 messages of a longer thread (`complete` is then false).

> "Summarise the thread about the office move."

### mark_messages

Mark as read or unread, flagged or unflagged.

### move_messages

Move messages between folders (e.g. to Archive or Trash). Nothing is deleted permanently.

## Spam rescue

### list_spam

What the spam filter caught: the Junk folder and, on mailcow, the quarantine, with sender,
subject, date and spam score.

> "Is there anything in spam that looks like a real reply from a customer?"

### rescue_from_junk

Moves messages from Junk to INBOX. On mailcow this also teaches the spam filter that they're
legitimate.

> "Move Pavel's message out of spam."

### release_from_quarantine

(mailcow) Releases a quarantined message: it's delivered to INBOX and the spam filter learns it as
not spam. Only for messages you recognise.

### delete_from_quarantine

(mailcow) Deletes a quarantined message permanently.

## mailcow extras

### delivery_status

Per recipient: delivered to the next server (`sent`), still retrying (`deferred`) or `bounced`,
with the receiving server's answer. Uses mailcow's recent mail log, so it covers recent mail only.

> "Did the email to the tax office get delivered?"

### my_addresses

Your mailbox address, its aliases (valid `from_address` values) and its name in mailcow. Mail
sent without `from_name` shows that name in From (generic mode and password sign-ins: just the
address).

> "Send it from my sales@ alias."

### find_contacts

Search your address books by name, email or organisation.

> "What's Jan Novák's email address?"
