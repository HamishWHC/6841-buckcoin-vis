import json
import re
from hashlib import sha256
from pprint import pprint

from bs4 import BeautifulSoup

COMMENT_CLASS = "css-4zwhzf-CommentCard"

BLOCK_REGEX = re.compile(
    r"(?P<block>(?P<chain_length>[0-9]+)\+(?P<prediction>[a-zA-Z0-9 _\-\.]+)\+.*(?P<prev_hash>[0-9a-fA-F]{64})\+(?P<serial_number>[0-9]+)).+(?P<claimed_hash>[0-9a-fA-F]{64})", flags=re.S)


def try_parse_int(s, base=10, val=None):
    try:
        return int(s, base)
    except ValueError:
        return val


def parse_blocks(text, author):
    blocks = {}

    for match in BLOCK_REGEX.finditer(text):
        groups = match.groupdict()
        blocks[groups["claimed_hash"].lower()] = {
            "author": author,
            "block": groups["block"],
            "prediction": groups["prediction"],
            "prev_hash": groups["prev_hash"].lower(),
            "hashes": {
                "claimed": groups["claimed_hash"].lower(),
                "actual": None,
            },
            "chain_lengths": {
                "claimed": try_parse_int(groups["chain_length"]),
                "actual": None
            },
            "serial_number": try_parse_int(groups["serial_number"]),
            "valid": None,
            "invalid_chain": None,
            "is_in_longest_valid_chain": False
        }

    return blocks


def read_blocks(html: str):
    soup = BeautifulSoup(html, "html.parser")

    blocks = {}

    for comment in soup.find_all("div", {"class": COMMENT_CLASS}):
        strings = list(comment.stripped_strings)
        author = strings[0]
        text = "\n".join(strings[2:])

        blocks = blocks | parse_blocks(text, author)

    return blocks


POTENTIAL_FORMATS = [
    lambda block: f"{block}\n",
    lambda block: block
]
default_format = POTENTIAL_FORMATS[0]


def hash_digest(hash):
    return hash[:8]


def correct_hash(block):
    return block["hashes"]["actual"] == block["hashes"]["claimed"]


def correct_length(block):
    return block["chain_lengths"]["expected"] == block["chain_lengths"]["claimed"]


def valid_hash(block):
    return block["hashes"]["claimed"][0] in "0123456789abcdef" and block["hashes"]["claimed"][1] in "0123456789"


def check_block_validity(blocks, block):
    if block["valid"] is not None:
        return

    for format in POTENTIAL_FORMATS:
        hash = sha256(format(block["block"]).encode()).hexdigest()
        if hash == block["hashes"]["claimed"]:
            block["hashes"]["actual"] = hash
            break
    else:
        hash = sha256(default_format(block["block"]).encode()).hexdigest()
        block["hashes"]["actual"] = hash

    prev = blocks.get(block["prev_hash"])
    if prev is None:
        block["chain_lengths"]["actual"] = 1
        block["chain_lengths"]["expected"] = 1
        block["invalid_chain"] = False
    else:
        check_block_validity(blocks, prev)
        block["chain_lengths"]["actual"] = prev["chain_lengths"]["actual"] + 1
        if not correct_length(prev):
            block["chain_lengths"]["expected"] = prev["chain_lengths"]["claimed"] + 1
        else:
            block["chain_lengths"]["expected"] = prev["chain_lengths"]["expected"] + 1
        block["invalid_chain"] = prev["valid"] is False or prev["invalid_chain"] is True

    block["valid"] = correct_hash(block) and correct_length(
        block) and valid_hash(block)


def check_chain_validity(blocks):
    for block in blocks.values():
        check_block_validity(blocks, block)

    return blocks


def block_formatter(block):
    issues = ""
    if block["valid"] is False:
        if not correct_hash(block):
            issues += f"""Expected hash: {hash_digest(block["hashes"]["actual"])}...\n"""
        if not valid_hash(block):
            issues += f"""Hash not starting with [0-9a-f][0-9]."""
        if not correct_length(block):
            issues += f"""Expected length: {block["chain_lengths"]["expected"]}, claimed: {block["chain_lengths"]["claimed"]}"""

    return f"""{hash_digest(block["hashes"]["claimed"])}["{hash_digest(block["hashes"]["claimed"])}...
{block["author"]}
{block["prediction"]}
Serial: {block["serial_number"]}
{"VALID" if block["valid"] else "INVALID"}{" (chain invalid)" if block["invalid_chain"] else ""}
{issues}"]"""


def link_formatter(link):
    return f"""{link["from"]}-->{link["to"]}"""


def backprop_longest_chain(blocks, block):
    block["is_in_longest_valid_chain"] = True
    prev = blocks.get(block["prev_hash"])
    if prev is not None:
        backprop_longest_chain(blocks, prev)


def generate_graph_md(blocks):
    links = []

    head = None

    for block in blocks.values():
        eligible = block["valid"] and not block["invalid_chain"]
        longest = head is None or block["chain_lengths"]["actual"] > head["chain_lengths"]["actual"]

        if eligible and longest:
            head = block

    if head:
        backprop_longest_chain(blocks, head)

    for block in blocks.values():
        prev = blocks.get(block["prev_hash"])
        link_in_chain = prev is not None and prev["is_in_longest_valid_chain"] and block["is_in_longest_valid_chain"]
        links.append({
            "from": hash_digest(block["prev_hash"]),
            "to": hash_digest(block["hashes"]["claimed"]),
            "in_longest_valid_chain": link_in_chain
        })

    flowchart_def = "\n".join([block_formatter(block)
                              for block in blocks.values()])

    links = sorted(links, key=lambda link: link["in_longest_valid_chain"])

    links_def = []
    last = False
    for link in links:
        if link["in_longest_valid_chain"] and not last:
            links_def.append("subgraph longest_chain")
        links_def.append(link_formatter(link))
        last = link["in_longest_valid_chain"]

    if last:
        links_def.append("end")

    links_def = "\n".join(links_def)

    return f"""```mermaid
flowchart TB
{flowchart_def}
{links_def}
```"""


BLOCKS_TO_INSERT = [
    ("""
1+Service NSW+0f603b5f322a16568bf7b0acff51008466408cdccbfeff675118bbde8ca49b50+11
083eaee1b4dc40f7ffa14d23b3ea78059b5cb3b529dc9e24f508160bcddd6e33
""", "Richard Buckland"),
    ("""
49+Valve Corporation+09e9d3191037561448e43d0f3d6f78806b646fccb95318b2505a69b5a1f60bd0+86
03c6c767415ebe1edb6b9f6efb198f8e1e71bbaec0144dad2b8b5a9462e89b78
""", "Korn"),
    ("""
103+Apple+01a278436dcb31a41945f484ae49fc9bb967ddb8f62379bdeddf38a36ae92353+61
087f5faa8ebe34762fdaae1e816d2b6bf4515e9c8a89eb56fab3683802f453d0
""", "Derek"),
    ("""
101+sleep+049bc085815d43d5960b0eb5a519bb0be1679f03ef815a3b9514f95697bbb3e9+13
095804d8ffe6e1e08354b6f29c2e1baf3487d53d466f0c4ecd06ec3aa51ea693
""", "Anahed"),
    ("""
100+Scomo+049bc085815d43d5960b0eb5a519bb0be1679f03ef815a3b9514f95697bbb3e9+8
08a9782b0680c7d37f27d64a8b17b01deb3dfb6bccdf3712292da7ffaf664a15
""", "Kelvin"),
    ("""
94+Sydney+07302bb69415abf63e0cbe7bc596be313cab8cfa3fdeb903def19b2fbebedaef+92
008dbcb12e520b2bdfef787d9d0394456042601e36e0d239e4dc09714b9ab736
""", "Yuanyuan")
]

EXCLUDED_BLOCKS = [
    "b62a3a072a6187d9a9df39dafa97de99154835d2531320f73e685173a8c7e78f",
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
]


if __name__ == "__main__":
    with open("in.html") as f:
        blocks = read_blocks(f.read())

    for block in BLOCKS_TO_INSERT:
        blocks = blocks | parse_blocks(*block)

    for block in EXCLUDED_BLOCKS:
        del blocks[block]

    blocks = check_chain_validity(blocks)

    with open("out.json", "w") as f:
        json.dump(blocks, f)

    graph_md = generate_graph_md(blocks)

    with open("out.md", "w") as f:
        f.write(graph_md)
