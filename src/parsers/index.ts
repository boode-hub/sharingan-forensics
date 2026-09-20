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
import { evtx } from './evtx';
import { prefetch } from './prefetch';
import { recycleBin } from './recyclebin';

register(recycleBin, prefetch, evtx);

export { recycleBin, prefetch, evtx };
