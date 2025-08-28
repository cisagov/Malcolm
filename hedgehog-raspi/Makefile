all: shasums

# List all the supported and built Pi platforms here. They get expanded
# to names like 'raspi_4_trixie.yaml' and 'raspi_5_trixie.img.xz'.
BUILD_FAMILIES := 4 5
BUILD_RELEASES := trixie

platforms := $(foreach plat, $(BUILD_FAMILIES),$(foreach rel, $(BUILD_RELEASES),  raspi_$(plat)_$(rel)))

shasums: $(addsuffix .img.sha256,$(platforms)) $(addsuffix .img.xz.sha256,$(platforms))
xzimages: $(addsuffix .img.xz,$(platforms))
images: $(addsuffix .img,$(platforms))
yaml: $(addsuffix .yaml,$(platforms))

ifeq ($(shell id -u),0)
as_root =
else ifneq (, $(shell which fakemachine))
$(warning "This should normally be run as root, but found 'fakemachine', so using that.")
as_root = fakemachine -v $(abspath $(CURDIR)/..) -- env --chdir $(abspath $(CURDIR))
else
$(error "This must be run as root")
endif

target_platforms:
	@echo $(platforms)

# Generate targets based on all family * release combinations:
define dynamic_yaml_target =
  raspi_$(1)_$(2).yaml: raspi_master.yaml generate-recipe.py
  raspi_$(1)_$(2).yaml:
	./generate-recipe.py $(1) $(2)
endef
$(foreach release,$(BUILD_RELEASES), \
  $(foreach family,$(BUILD_FAMILIES), \
    $(eval $(call dynamic_yaml_target,$(family),$(release)))))

%.img.sha256: %.img
	echo $@
	sha256sum $< > $@

%.img.xz.sha256: %.img.xz
	echo $@
	sha256sum $< > $@

%.img.xz: %.img
	xz -f -k -z -9 $<

%.img.bmap: %.img
	bmaptool create -o $@ $<

%.img: %.yaml
	touch $(@:.img=.log)
	time nice $(as_root) vmdb2 --verbose --rootfs-tarball=$(subst .img,.tar.gz,$@) --output=$@ $(subst .img,.yaml,$@) --log $(subst .img,.log,$@)
	chmod 0644 $@ $(@,.img=.log)

_ck_root:
	[ `whoami` = 'root' ] # Only root can summon vmdb2 ☹

_clean_yaml:
	rm -f $(addsuffix .yaml,$(platforms)) raspi_base_trixie.yaml
_clean_images:
	rm -f $(addsuffix .img,$(platforms))
_clean_xzimages:
	rm -f $(addsuffix .img.xz,$(platforms))
_clean_bmaps:
	rm -f $(addsuffix .img.bmap,$(platforms))
_clean_shasums:
	rm -f $(addsuffix .img.sha256,$(platforms)) $(addsuffix .img.xz.sha256,$(platforms))
_clean_logs:
	rm -f $(addsuffix .log,$(platforms))
_clean_tarballs:
	rm -f $(addsuffix .tar.gz,$(platforms))
clean: _clean_xzimages _clean_images _clean_shasums _clean_yaml _clean_tarballs _clean_logs _clean_bmaps

.PHONY: _ck_root _build_img clean _clean_images _clean_yaml _clean_tarballs _clean_logs
