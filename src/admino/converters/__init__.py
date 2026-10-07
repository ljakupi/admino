"""Document conversion pipeline (GH-188): uploaded attachments to model-ready parts.

``common`` holds the shared limits, failure codes, text helpers, the part writer
and the manifest models. The parsers (``pdf``, ``word``, ``sheets``, ``images``,
``dispatch``, ``worker``) run only in the short-lived worker child that
``runner`` starts; the server process never imports them.
"""
