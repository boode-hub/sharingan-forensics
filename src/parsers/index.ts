/**
 * Registers every implemented parser. Importing this module is what makes
 * `detect()` able to see them — the worker imports it, the tests import it.
 * Add one line per parser as phases land; see SPEC.md for the roadmap.
 */
import { register } from '../core/registry';

register();

export {};
