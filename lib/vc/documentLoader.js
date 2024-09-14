/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
// load locally embedded contexts

export async function documentLoader(url) {
  throw new Error(`Document loader unable to load URL "${url}".`);
}
