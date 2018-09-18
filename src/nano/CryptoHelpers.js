/** @module utils/CryptoHelpers */

import CryptoHelpersLegacy from './CryptoHelpersLegacy';
import * as helpers from '../utils/helpers/';
import * as keyPair1 from '../crypto/keyPair';
import * as address1 from '../model/address';

/**
 * Create BIP32 data
 *
 * @param {string} childKey - A child private key
 * @param {number} network - A network
 *
 * @return {object} - The BIP32 data
 */
let createBIP32Data = function (childKey, network) {
    let privateKey = helpers.fixPrivateKey(childKey);

    let keyPair =keyPair1.create(privateKey);
    let publicKey = keyPair.publicKey.toString();
    let address = address1.toAddress(publicKey, network);

    return {
        address,
        privateKey,
        publicKey,
    };
};

/**
 * Generate BIP32 data
 *
 * @param {string} privateKey - A private key
 * @param {string} password - A wallet password
 * @param {number} index - A derivation index
 * @param {number} network - A network
 *
 * @return {object|promise} - The BIP32 data or promise error
 */
let generateBIP32Data = function (privateKey, password, index, network) {
    return new Promise((resolve, reject) => {
        if (!privateKey) return reject("No private key");
        if (!helpers.isPrivateKeyValid(privateKey)) return reject("Private key is invalid");
        if (!password) return reject("No password");
        if (!network) return reject("No network");

        let childKey = CryptoHelpersLegacy.generateBIP32Data(privateKey, password, index);

        let data = createBIP32Data(childKey, network);

        resolve(data);
    });
};

module.exports = {
    generateBIP32Data,
};
