
python_src     := filescan
pb_schema_in   := $(python_src)/strelka/proto/strelka.proto
pb_schema_out  := $(python_src)/strelka/proto
out_base       := $(pb_schema_out)/$(basename $(notdir $(pb_schema_in)))
out_python     := $(out_base)_pb2.py
out_pystub     := $(out_base)_pb2.pyi
out_pygrpc     := $(out_base)_pb2_grpc.py
out_files      := $(out_python) $(out_pystub) $(out_pygrpc) $(out_pygrpclib)

PYTHON         ?= python3
PROTOC         := $(PYTHON) -m grpc_tools.protoc


.PHONY: all
all: $(out_files)

.PHONY: clean
clean:
	find $(python_src) -iname __pycache__ -type d -exec rm -rf {} \+
	rm -f $(out_files)
	rm -rf python-statfs/build python-statfs/python_statfs.egg-info

.PRECIOUS: $(out_files)
$(out_files): $(pb_schema_in)
	$(PROTOC) \
		-I$(<D) \
		--python_out=$(@D) \
		--pyi_out=$(@D) \
		--grpc_python_out=$(@D) \
		$<
	sed -i -re 's/import strelka_pb2/from . \0/' $(out_files)

