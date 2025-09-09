import { hash } from "internxt-crypto";

const SAS_BIT_LENGTH = 48;

/**
 * Generates a SAS composed of emojies.
 * Borrowed from the Matrix JS SDK.
 *
 * @param {string} data - The string from which to generate SAS.
 * @returns {Promise<string[][]>} The SAS emojies.
 */
export async function generateEmojiSas(data: string): Promise<string[][]> {
    const sasBytes = await hash.getBitsFromString(SAS_BIT_LENGTH, data);
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

export const emojiMapping = [
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
