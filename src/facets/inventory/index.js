// Retired facet class (pod-kernel-2). The generic FacetStore (src/facet_store.js)
// replaces it. Kept ONLY because wrangler migration tag v2 declared this class:
// migrations are append-only, and removing a class needs a deleted_classes step
// that destroys its storage -- a release never does that. No binding, no route,
// no method: any storage an older pod created stays where it is, untouched.
import { DurableObject } from "cloudflare:workers";

export class InventoryFacet extends DurableObject {}
