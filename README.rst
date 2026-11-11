PQTrust: Post-Quantum Trust Registry
====================================

PQTrust is a small, dependency-free Python package that ships a curated
registry of trusted signing-key fingerprints, including post-quantum
algorithms such as ML-DSA and SLH-DSA, and lets applications ask
"is this key trusted today?" in constant time.

Installation
------------

.. code-block:: console

    $ pip install .

Usage
-----

.. code-block:: python

    >>> import pqtrust
    >>> registry = pqtrust.load_default()
    >>> registry.is_trusted("0" * 64)
    False
    >>> [a.name for a in registry.expiring_within(365)]

From the command line:

.. code-block:: console

    $ python -m pqtrust list
    $ python -m pqtrust check <fingerprint>
    $ python -m pqtrust expiring --days 180
    $ python -m pqtrust fingerprint mykey.bin

Project layout
--------------

* ``pqtrust/models.py``   - validated, immutable ``Anchor`` dataclass
* ``pqtrust/registry.py`` - ``TrustRegistry`` (dict, heap, defaultdict, atomic JSON save)
* ``pqtrust/audit.py``    - bounded ``deque`` audit log + JSONL file
* ``pqtrust/core.py``     - path lookup and chunked SHA3-256 hashing
* ``pqtrust/anchors.json``- bundled sample registry data
* ``normalize-registry``  - validates and rewrites the JSON data file
* ``tests/``              - pytest suite

Testing
-------

.. code-block:: console

    $ make test

License
-------

MIT. See ``LICENSE``. Sample data is fictional and must not be used for
real security decisions.
