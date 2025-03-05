const emojiMapping = [
    ["🐶", "dog"],
    ["🐱", "cat"],
    ["🦁", "lion"],
    ["🐎", "horse"],
    ["🦄", "unicorn"],
    ["🐷", "pig"],
    ["🐘", "elephant"],
    ["🐰", "rabbit"],
    ["🐼", "panda"],
    ["🐓", "rooster"],
    ["🐧", "penguin"],
    ["🐢", "turtle"],
    ["🐟", "fish"],
    ["🐙", "octopus"],
    ["🦋", "butterfly"],
    ["🌷", "flower"],
    ["🌳", "tree"],
    ["🌵", "cactus"],
    ["🍄", "mushroom"],
    ["🌏", "globe"],
    ["🌙", "moon"],
    ["☁️", "cloud"],
    ["🔥", "fire"],
    ["🍌", "banana"],
    ["🍎", "apple"],
    ["🍓", "strawberry"],
    ["🌽", "corn"],
    ["🍕", "pizza"],
    ["🎂", "cake"],
    ["❤️", "heart"],
    ["🙂", "smiley"],
    ["🤖", "robot"],
    ["🎩", "hat"],
    ["👓", "glasses"],
    ["🔧", "spanner"],
    ["🎅", "santa"],
    ["👍", "thumbs up"],
    ["☂️", "umbrella"],
    ["⌛", "hourglass"],
    ["⏰", "clock"],
    ["🎁", "gift"],
    ["💡", "light bulb"],
    ["📕", "book"],
    ["✏️", "pencil"],
    ["📎", "paperclip"],
    ["✂️", "scissors"],
    ["🔒", "lock"],
    ["🔑", "key"],
    ["🔨", "hammer"],
    ["☎️", "telephone"],
    ["🏁", "flag"],
    ["🚂", "train"],
    ["🚲", "bicycle"],
    ["✈️", "aeroplane"],
    ["🚀", "rocket"],
    ["🏆", "trophy"],
    ["⚽", "ball"],
    ["🎸", "guitar"],
    ["🎺", "trumpet"],
    ["🔔", "bell"],
    ["⚓️", "anchor"],
    ["🎧", "headphones"],
    ["📁", "folder"],
    ["📌", "pin"],
];

/**
 * Generates a SAS composed of defimal numbers.
 * Borrowed from the Matrix JS SDK.
 *
 * @param {Uint8Array} sasBytes - The bytes from sas.generate_bytes.
 * @returns Array<number>
 */
export function generateEmojiSas(sasBytes: Uint8Array) {
    // Just like base64.
    const emojis = [
        sasBytes[0] >> 2,
        ((sasBytes[0] & 0x3) << 4) | (sasBytes[1] >> 4),
        ((sasBytes[1] & 0xf) << 2) | (sasBytes[2] >> 6),
        sasBytes[2] & 0x3f,
        sasBytes[3] >> 2,
        ((sasBytes[3] & 0x3) << 4) | (sasBytes[4] >> 4),
        ((sasBytes[4] & 0xf) << 2) | (sasBytes[5] >> 6),
    ];

    return emojis.map((num) => emojiMapping[num]);
}
