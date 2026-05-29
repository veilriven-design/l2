# src

this is where the actual c lives.

## model

l2 systems are the thing. you make them, you use them, you kill them. everything you can do to one goes through the functions in sys.h (the l2_sys_* ones).

see docs/system_model.md if you want the more formal version.

## how we're thinking about it

- the interface has to stay tiny
- stuff inside a system shouldn't be able to reach outside unless we explicitly let it
- the core that creates and manages systems should be as small as we can make it
- memory safety matters a lot here (see memory_safety.md)

## rough layout right now

```
src/
├── core/
│   └── sys.h          # the actual api (l2_sys_create etc)
├── common/
│   └── safe.*         # the guards we actually use
└── ...
```

this is still early. don't expect nice structure yet.
