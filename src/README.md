# src

actual c lives here

-/ model

l2 systems -/ make them - use them - kill them

everything goes through functions in sys-h -/ the l2_sys_* ones

see docs/system_model-md for more formal take

-/ how we think about it

- interface must stay tiny
- stuff inside must not reach outside unless explicitly allowed
- core that manages systems must stay as small as possible
- memory safety matters -/ see memory_safety-md

-/ rough layout

```
src/
├── core/
│   └── sys.h     # actual api - l2_sys_create etc
├── common/
│   └── safe-*    # guards
└── ...
```

still early -/ dont expect clean structure yet
