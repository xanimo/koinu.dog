# koinu.dog

the site, live at [koinu.dog](https://koinu.dog/). the wallet is
[xanimo/koinu](https://github.com/xanimo/koinu) and it is a submodule here,
pinned to the commit the pages are written against.

    git clone --recurse-submodules https://github.com/xanimo/koinu.dog
    pip install ziglang==0.17.0
    ./build.sh

the deploy serves `index.html`, `koinu.js` and `koinu.wasm`, the font subsets
under `fonts/`, and a `CNAME` naming the domain. the first two are in the
repository and the wasm is a build output, so it is gitignored and the pages
workflow compiles it on every deploy. that is the point: the module the page
runs comes from the koinu commit this repository pins, so the claim the learn
pages make, that the panels run the same files kw links, can be checked rather
than taken on trust.

the page fetches nothing from anyone else. ubuntu and ubuntu mono are subset
into `fonts/` rather than requested from google, with a dejavu subset bound to
the same family for the box-drawing and arrow glyphs ubuntu mono does not carry.
the `CNAME` ships with the build because an actions deploy publishes whatever
the artifact holds, and one without it can clear the custom domain.

the version the footer prints is stamped at deploy from
`koinu/include/kw_version.h`, so moving the submodule carries it. the step fails
rather than publishing a stale number if the header yields nothing or the
substitution finds no target.

`kw_web.c` is the only code here that is not koinu's. it wraps the library in
string-in, json-out calls and nothing in it reimplements a primitive. two things
differ from the native build and it says so in its first comment: randomness
comes from the browser's `crypto.getRandomValues`, and nothing is mlock'd,
because wasm linear memory has no pages to pin. it is a teaching build, not a
wallet.

the build is reproducible. ziglang 0.17.0 with the pinned submodules gives a
byte-identical `koinu.wasm`, and the deploy prints its sha256, so a local run
can be compared against what is published. at koinu v0.4.0 that is 406571
bytes.

## moving to a newer koinu
 
    git -C koinu fetch origin
    git -C koinu checkout <commit>
    git submodule update --init --recursive
    ./build.sh
    git add koinu && git commit

the panels call `kwj_` functions in `kw_web.c`, which call the library through
its public headers, so a koinu commit that changes one of those signatures
breaks the build here rather than the page. `koinu/docs/abi.md` says which types
can move and which cannot.
