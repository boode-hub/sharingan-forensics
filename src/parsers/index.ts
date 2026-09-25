/**
 * Registers every implemented parser. Importing this module is what makes
 * `detect()` able to see them — the worker imports it, the tests import it.
 * Add one line per parser as phases land; see SPEC.md for the roadmap.
 *
 * A parser that is written, tested and NOT listed here is invisible to the app,
 * so `detect.test.ts` asserts that every fixture directory resolves to a
 * registered parser.
 */
import { register } from '../core/registry';
import { amcache } from './amcache';
import { appCompatCache } from './appcompatcache';
import { evtx } from './evtx';
import { jumplist } from './jumplist';
import { lnk } from './lnk';
import { boot } from './boot';
import { i30 } from './i30';
import { mft } from './mft';
import { sds } from './sds';
import { usnJrnl } from './usnjrnl';
import { prefetch } from './prefetch';
import { registry } from './registry';
import { shellbags } from './shellbags';
import { recentFileCache } from './recentfilecache';
import { recycleBin } from './recyclebin';

// Amcache before the plain hive: both claim a regf file, and an Amcache.hve
// is read as Amcache first.
register(recycleBin, prefetch, evtx, lnk, jumplist, amcache, registry, shellbags, appCompatCache, mft, usnJrnl, boot, sds, i30, recentFileCache);

export { recycleBin, prefetch, evtx, lnk, jumplist, amcache, registry, shellbags, appCompatCache, mft, usnJrnl, boot, sds, i30, recentFileCache };
