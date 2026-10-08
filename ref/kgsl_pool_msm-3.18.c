/* kgsl_pool.c - msm-3.18 (android-linux-stable kernel.lnx.3.18.r34-rel)
 * Fetched 2026-10-10 for the KEYone KGSL UAF lane (notes/58).
 * Key facts for the exploit: freed KGSL pages go into per-order FIFO pools
 * while kgsl_pool_size_total() < kgsl_pool_max_pages (DT qcom,mempool-max-pages),
 * else __free_pages(); pool adds ZERO the page; allocation takes the oldest
 * (head) page; kgsl_pool_shrinker drains pools under memory pressure;
 * kgsl_gfp_mask(0) = __GFP_HIGHMEM | GFP_KERNEL (UNMOVABLE).
 */
