#include "nest/bird.h"

#include "filter/filter.h"
#include "nest/route.h"

_Static_assert(sizeof(struct f_val) >= sizeof(struct eattr), "Structures f_val and eattr not binary compatible!");
_Static_assert(OFFSETOF(struct f_val, val) == OFFSETOF(struct eattr, u), "Structures f_val and eattr not binary compatible!");
_Static_assert(sizeof(enum ea_type) == sizeof(enum f_type), "Structures f_val and eattr not binary compatible!");
