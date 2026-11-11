.PHONY: test normalize build clean

test:
	python -m pytest -q

normalize:
	python normalize-registry

build: clean
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache
