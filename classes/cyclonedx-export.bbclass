# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright (C) 2022 BG Networks, Inc.
# SPDX-FileCopyrightText: Copyright (C) 2024 Savoir-faire Linux Inc. (<www.savoirfairelinux.com>).
# SPDX-FileCopyrightText: Copyright (C) 2024 iris-GmbH infrared & intelligent sensors.
# SPDX-FileCopyrightText: Copyright (C) 2025 balena, inc.

# The product name that the CVE database uses.  Defaults to BPN, but may need to
# be overriden per recipe (for example tiff.bb sets CVE_PRODUCT=libtiff).
CVE_PRODUCT ??= "${BPN}"
CVE_VERSION ??= "${PV}"

CYCLONEDX_RUNTIME_PACKAGES_ONLY ??= "1"

CYCLONEDX_EXPORT_DIR ??= "${DEPLOY_DIR}/cyclonedx-export/${PN}"
CYCLONEDX_EXPORT_SBOM ??= "${CYCLONEDX_EXPORT_DIR}/bom.json"
CYCLONEDX_EXPORT_VEX ??= "${CYCLONEDX_EXPORT_DIR}/vex.json"
CYCLONEDX_TMP_WORK_DIR ??= "${WORKDIR}/cyclonedx"
CYCLONEDX_TMP_PN_LIST = "${CYCLONEDX_TMP_WORK_DIR}/pn-list.json"
CYCLONEDX_WORK_DIR_ROOT ??= "${TMPDIR}/cyclonedx"
CYCLONEDX_WORK_DIR = "${CYCLONEDX_WORK_DIR_ROOT}/${PN}"
CYCLONEDX_WORK_DIR_PN_LIST = "${CYCLONEDX_WORK_DIR}/pn-list.json"

# We need to add the sbom serial number to the list of vulnerabilites for each recipe but
# don't know it until after we generate the sbom export header file
CYCLONEDX_SBOM_SERIAL_PLACEHOLDER = "<SBOM_SERIAL>"

# resolve CVE_CHECK_IGNORE and CVE_STATUS_GROUPS,
# taken from https://git.yoctoproject.org/poky/commit/meta/classes/cve-check.bbclass?id=be9883a92bad0fe4c1e9c7302c93dea4ac680f8c
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright OpenEmbedded Contributors
python () {
    # Fallback all CVEs from CVE_CHECK_IGNORE to CVE_STATUS
    cve_check_ignore = d.getVar("CVE_CHECK_IGNORE")
    if cve_check_ignore:
        bb.warn("CVE_CHECK_IGNORE is deprecated in favor of CVE_STATUS")
        for cve in (d.getVar("CVE_CHECK_IGNORE") or "").split():
            d.setVarFlag("CVE_STATUS", cve, "ignored")

    # Process CVE_STATUS_GROUPS to set multiple statuses and optional detail or description at once
    for cve_status_group in (d.getVar("CVE_STATUS_GROUPS") or "").split():
        cve_group = d.getVar(cve_status_group)
        if cve_group is not None:
            for cve in cve_group.split():
                d.setVarFlag("CVE_STATUS", cve, d.getVarFlag(cve_status_group, "status"))
        else:
            bb.warn("CVE_STATUS_GROUPS contains undefined variable %s" % cve_status_group)

    # nnounce: register threat-model CVE_STATUS keywords so oe.cve_check maps them to
    # "Ignored" instead of warning and defaulting to "Unpatched". append_to_vex renders
    # these as not_affected + CycloneDX justification "protected_at_perimeter" (the CVE
    # is real but unreachable across the device's access perimeter). Setting these flags
    # is additive -- it does not disturb the standard poky CVE_CHECK_STATUSMAP entries.
    for _tm_kw in ("requires-authentication", "requires-local-access", "requires-physical-access"):
        d.setVarFlag("CVE_CHECK_STATUSMAP", _tm_kw, "Ignored")

    # do_cyclonedx_package_collect reads the recipe's CVE_STATUS only through
    # get_patched_cves() (an external oe.cve_check function), so bitbake's signature
    # parser never sees CVE_STATUS and the task is NOT rebuilt when a status changes.
    # With a shared sstate cache that means adding a CVE_STATUS (e.g. in the
    # meta-nnounce-cve layer) is silently ignored -- the stale cached VEX is restored
    # and the CVE never reaches the VEX. Fold the resolved CVE_STATUS flags (computed
    # AFTER the groups above) into a signature variable that the task DOES depend on,
    # so any status change invalidates the cache and regenerates the VEX.
    _cve_status_flags = d.getVarFlags("CVE_STATUS") or {}
    d.setVar("CYCLONEDX_CVE_STATUS_SIG",
             ";".join("%s=%s" % (k, _cve_status_flags[k])
                      for k in sorted(_cve_status_flags) if not k.startswith("_")))
}

# Note: We don't clean the entire CYCLONEDX_WORK_DIR_ROOT on BuildStarted anymore
# as it interferes with sstate restoration. Each recipe's work dir is managed
# by the sstate mechanism through do_populate_cyclonedx[cleandirs] = "${CYCLONEDX_WORK_DIR}"
# which cleans only when the task actually runs, not when restored from sstate.

python do_cyclonedx_package_collect() {
    """
    Collect package information and CVE data from all packages built for the target architecture.
    """
    from oe.cve_check import get_patched_cves

    pn = d.getVar("PN")

    # ignore non-target packages
    for ignored_suffix in (d.getVar("SPECIAL_PKGSUFFIX") or "").split():
        if pn.endswith(ignored_suffix):
            return

    # get all CVE product names and version from the recipe
    name = d.getVar("CVE_PRODUCT")
    version = d.getVar("CVE_VERSION")

    # We create and populate a per-recipe partial sbom which will be added to the sstate cache
    pn_list = {}
    pn_list["pkgs"] = []
    cves = []
    # append all defined package names for recipe to pn_list pkgs
    for pkg in generate_packages_list(d, name, version):
        if not next((c for c in pn_list["pkgs"] if c["cpe"] == pkg["cpe"]), None):
            pn_list["pkgs"].append(pkg)
            bom_ref = pkg["bom-ref"]

            # append any CVEs either patched or taken from CVE_STATUS
            for cve_id, cve_info in get_patched_cves(d).items():
                cve = (
                    cve_id,
                    cve_info["abbrev-status"],
                    cve_info["status"],
                    cve_info.get("justification", "")
                )
                append_to_vex(d, cve, cves, bom_ref)

    # append any cve status within recipe to pn_list cves
    pn_list["cves"] = cves

    # Add dependencies
    dependencies = []

    for comp in pn_list["pkgs"]:
        main_ref = comp.get("bom-ref")
        if not main_ref:
            continue

        dep_entry = {
            "ref": main_ref,
            "dependsOn": []
        }

        for dep_name in get_recipe_dependencies(d):
            dep_entry["dependsOn"].append(dep_name)

        if dep_entry["dependsOn"]:
            dependencies.append(dep_entry)

    pn_list["dependencies"] = dependencies

    # write partial sbom to the recipes work folder
    write_json(d.getVar("CYCLONEDX_TMP_PN_LIST"), pn_list)
}

addtask do_cyclonedx_package_collect before do_build
do_cyclonedx_package_collect[cleandirs] = "${CYCLONEDX_TMP_WORK_DIR}"
# Force task to run when bbclass changes
# CYCLONEDX_CVE_STATUS_SIG: rebuild when any CVE_STATUS changes (see anon python above).
# SRC_URI: rebuild when a CVE-*.patch is added/removed (get_patched_cves derives the
# "Patched" set from patch filenames in SRC_URI, which the task body doesn't reference).
do_cyclonedx_package_collect[vardeps] += "generate_packages_list append_to_vex get_recipe_dependencies CYCLONEDX_CVE_STATUS_SIG SRC_URI"

# Utilizing shared state for output caching
# see https://docs.yoctoproject.org/overview-manual/concepts.html#shared-state
SSTATETASKS += "do_populate_cyclonedx"
do_populate_cyclonedx() {
    bbnote "Deploying intermediate product name list files from ${CYCLONEDX_TMP_WORK_DIR} to ${CYCLONEDX_WORK_DIR}"
}
python do_populate_cyclonedx_setscene() {
    sstate_setscene(d)
}

do_populate_cyclonedx[cleandirs] = "${CYCLONEDX_WORK_DIR}"
do_populate_cyclonedx[sstate-inputdirs] = "${CYCLONEDX_TMP_WORK_DIR}"
do_populate_cyclonedx[sstate-outputdirs] = "${CYCLONEDX_WORK_DIR}"
addtask do_populate_cyclonedx_setscene
addtask do_populate_cyclonedx after do_cyclonedx_package_collect
# Note: do_rootfs[recrdeptask] is set in __anonymous() for image recipes only

def read_json(path):
    import json
    from pathlib import Path
    return json.loads(Path(path).read_text())

def write_json(path, content):
    import json
    from pathlib import Path
    Path(path).write_text(
        json.dumps(content, indent=2)
    )


def get_recipe_dependencies(d):
    """
    Return recipe names which depend on the current one.
    """
    pn = d.getVar("PN")
    runtime_deps = (d.getVar("RDEPENDS:" + pn) or "").split()
    build_deps = (d.getVar("DEPENDS") or "").split()
    deps = build_deps + runtime_deps
    ignored_suffixes = set((d.getVar("SPECIAL_PKGSUFFIX") or "").split())
    # Resolves virtual/* dependencies to their preferred providers.
    resolved_deps = set()
    for dep in deps:
        dep = dep.strip()
        if not dep:
            continue
        # If package is virtual, we retrieve his provider
        if dep.startswith("virtual/"):
            dep = d.getVar("PREFERRED_RPROVIDER_" + dep) or d.getVar("PREFERRED_PROVIDER_" + dep) or dep
        # ignore non-target packages
        if any(dep.endswith(suffix) for suffix in ignored_suffixes):
            continue

        resolved_deps.add(dep)
    return list(resolved_deps)

def resolve_dependency_ref(depends, bom_ref_map, alias_map):
    """
    Replace dependency name by his bom-ref attribute
    """

    # Direct
    if depends in bom_ref_map:
        return bom_ref_map[depends]["bom-ref"]

    # By Alias
    if depends in alias_map:
        real_name = alias_map[depends]
        if real_name in bom_ref_map:
            return bom_ref_map[real_name]["bom-ref"]

    # Return None if no solution found
    return None

def generate_packages_list(d, products_names, version):
    """
    Get a list of products and generate CPE and PURL identifiers for each of them.
    """
    import uuid
    import re

    # Extract license information from recipe
    license = d.getVar("LICENSE") or ""

    # Map non-SPDX Yocto licenses to SPDX equivalents
    license_map = {
        "CLOSED": "NOASSERTION",
        "PD": "CC0-1.0",  # Public Domain mapped to CC0
        "Proprietary": "Proprietary",  # Will use name field
    }

    # Convert Yocto license format to CycloneDX format
    licenses_list = None
    if license:
        # Clean up the license string
        license_clean = license.strip()

        # Map known non-SPDX licenses
        for old, new in license_map.items():
            license_clean = license_clean.replace(old, new)

        # Process the license
        if license_clean:
            # Check if it's a complex expression (contains & or |)
            if re.search(r'[&|()]', license_clean):
                # Use expression field for complex licenses
                # Clean up extra spaces
                license_expr = re.sub(r'\s+', ' ', license_clean).strip()
                licenses_list = [{"expression": license_expr}]
            else:
                # Simple single license
                # Check if it's a LicenseRef, NOASSERTION, or non-SPDX license - use name field
                # Common non-standard licenses that should use name instead of id:
                # - Licenses with exceptions (e.g., "GPL-2.0-with-OpenSSL-exception")
                # - Custom/vendor licenses (e.g., "BitstreamVera")
                # - LicenseRef- prefixed licenses
                non_standard_markers = [
                    "LicenseRef-",
                    "Proprietary",
                    "NOASSERTION",
                    "-with-",  # License exceptions
                    "BitstreamVera",
                    "Commercial",
                    "Evaluation",
                ]

                is_non_standard = any(marker in license_clean for marker in non_standard_markers)

                if is_non_standard:
                    licenses_list = [{"license": {"name": license_clean}}]
                else:
                    # Standard SPDX license - use id field
                    licenses_list = [{"license": {"id": license_clean}}]

    packages = []

    # keep only the short version which can be matched against vulnerabilities databases
    version = version.split("+git")[0]

    # some packages have alternative names, so we split CVE_PRODUCT
    # convert to set to avoid duplicates
    for product in set(products_names.split()):
        # CVE_PRODUCT in recipes may include vendor information for CPE identifiers. If not,
        # use wildcard for vendor.
        if ":" in product:
            vendor, product = product.split(":", 1)
        else:
            vendor = ""

        pkg = {
            "name": product,
            "version": version,
            "type": "library",
            "cpe": 'cpe:2.3:*:{}:{}:{}:*:*:*:*:*:*:*'.format(vendor or "*", product, version),
            "purl": 'pkg:generic/{}{}@{}'.format(f"{vendor}/" if vendor else '', product, version),
            "bom-ref": str(uuid.uuid4()),
        }
        if vendor != "":
            pkg["group"] = vendor
        if licenses_list:
            pkg["licenses"] = licenses_list
        packages.append(pkg)
    return packages

def append_to_vex(d, cve, cves, bom_ref):
    """
    Collect CVE status information from within open embedded recipes and append to add to cve dictionary.
    This could be backported, patched or ignored CVEs.
    """
    cve_id, abbrev_status, status, justification = cve

    # nnounce threat-model categories (see THREATMODEL_JUSTIFICATION below): the CVE is
    # real, but the attacker cannot cross the device's access perimeter -- it needs an
    # already-authenticated user, or local, or physical access. On a sealed appliance
    # these cross no trust boundary, so we render them "not_affected" with a machine-
    # readable CycloneDX justification of "protected_at_perimeter" -> Dependency-Track
    # hides them. The specific precondition stays in the detail (STATE:/JUSTIFICATION:)
    # and in the CVE_STATUS description, so the disposition remains auditable/reversible.
    # https://cyclonedx.org/docs/1.4/json/#vulnerabilities_items_analysis_justification
    THREATMODEL_JUSTIFICATION = {
        "requires-authentication": "protected_at_perimeter",
        "requires-local-access": "protected_at_perimeter",
        "requires-physical-access": "protected_at_perimeter",
    }

    cdx_justification = None
    # Currently, only "Patched" and "Ignored" status are relevant to us.
    # See https://docs.yoctoproject.org/singleindex.html#term-CVE_CHECK_STATUSMAP for possible statuses.
    if status.strip() in THREATMODEL_JUSTIFICATION:
        # Keyed on the CVE_STATUS keyword directly, so it works even if the keyword is
        # not in CVE_CHECK_STATUSMAP (abbrev_status would otherwise be "Unpatched").
        bb.debug(2, f"Found threat-model status '{status}' for {cve_id} in {d.getVar('BPN')}")
        vex_state = "not_affected"
        cdx_justification = THREATMODEL_JUSTIFICATION[status.strip()]
    elif abbrev_status == "Patched":
        bb.debug(2, f"Found patch for {cve_id} in {d.getVar('BPN')}")
        vex_state = "resolved"
    elif abbrev_status == "Ignored":
        bb.debug(2, f"Found ignore statement for {cve_id} in {d.getVar('BPN')}")
        vex_state = "not_affected"
    else:
        bb.debug(2, f"Found unknown or irrelevant CVE status {abbrev_status} for {cve_id} in {d.getVar('BPN')}. Skipping...")
        return

    detail_string = ""
    detail_string += f"STATE: {status}\n"
    if justification:
        detail_string += f"JUSTIFICATION: {justification}\n"

    analysis = {
        "state": vex_state,
        "detail": detail_string,
    }
    # CycloneDX requires a justification for the not_affected state to be actionable;
    # only our threat-model statuses set one (the Yocto Ignored statuses carry their
    # reasoning in the detail string only, as before).
    if cdx_justification:
        analysis["justification"] = cdx_justification

    cves.append({
        "id": cve_id,
        # vex documents require a valid source, see https://github.com/DependencyTrack/dependency-track/issues/2977
        # this should always be NVD for yocto CVEs.
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        "analysis": analysis,
        "affects": [{"ref": f"urn:cdx:{d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER')}/1#{bom_ref}"}]
    })
    return

python do_deploy_cyclonedx() {
    """
    Select CVE and package information and runtime packages and output them into a single export file.
    Only runs for image recipes.
    """
    # This task should only run for image recipes
    if not bb.data.inherits_class('image', d):
        bb.note("Skipping do_deploy_cyclonedx for non-image recipe")
        return

    from oe.rootfs import image_list_installed_packages
    import uuid
    from datetime import datetime, timezone
    import os

    timestamp = datetime.now(timezone.utc).isoformat()

    # Generate unique serial numbers for sbom and vex document
    sbom_serial_number = str(uuid.uuid4())
    vex_serial_number = str(uuid.uuid4())

    cyclonedx_work_dir_root = d.getVar("CYCLONEDX_WORK_DIR_ROOT")

    # Generate sbom document header
    bb.debug(2, f"Creating empty temporary sbom file with serial number {sbom_serial_number}")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{sbom_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "components": [],
        "dependencies": []
    }

    # Generate vex document header
    bb.debug(2, f"Creating empty temporary vex file with serial number {sbom_serial_number}")
    vex = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{vex_serial_number}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"name": "yocto"}]
        },
        "vulnerabilities": []
    }

    # taken from https://github.com/yoctoproject/poky/blob/fec201518be3c35a9359ec8c37675a33e458b92d/meta/classes/cve-check.bbclass
    # SPDX-License-Identifier: MIT
    # SPDX-FileCopyrightText: Copyright OpenEmbedded Contributors
    # Collect sbom data from runtime packages

    recipes = set()
    if d.getVar('CYCLONEDX_RUNTIME_PACKAGES_ONLY') == "1":
        # Use IMAGE_MANIFEST instead of image_list_installed_packages to avoid dnf query issues
        manifest_file = d.getVar('IMAGE_MANIFEST')
        bb.note(f"IMAGE_MANIFEST from d.getVar: {manifest_file}")

        # If IMAGE_MANIFEST is not set or doesn't exist, try to find it
        if not manifest_file or not os.path.exists(manifest_file):
            # Try to construct the path manually
            deploy_dir_image = d.getVar('IMGDEPLOYDIR')
            image_link_name = d.getVar('IMAGE_LINK_NAME')
            bb.note(f"IMGDEPLOYDIR: {deploy_dir_image}, IMAGE_LINK_NAME: {image_link_name}")
            if deploy_dir_image and image_link_name:
                manifest_file = os.path.join(deploy_dir_image, f"{image_link_name}.manifest")
                bb.note(f"Trying constructed path: {manifest_file}, exists: {os.path.exists(manifest_file)}")

            # Try alternate location in deploy-complete
            if not manifest_file or not os.path.exists(manifest_file):
                workdir = d.getVar('WORKDIR')
                image_name = d.getVar('IMAGE_NAME')
                if workdir and image_name:
                    # Try deploy-image-complete directory
                    alt_path = os.path.join(workdir, f"deploy-{d.getVar('PN')}-image-complete", f"{image_name}.manifest")
                    bb.note(f"Trying alternate path: {alt_path}, exists: {os.path.exists(alt_path)}")
                    if os.path.exists(alt_path):
                        manifest_file = alt_path

        bb.note(f"CYCLONEDX_WORK_DIR_ROOT: {cyclonedx_work_dir_root}")
        if manifest_file and os.path.exists(manifest_file):
            bb.note(f"Reading package list from manifest: {manifest_file}")
            with open(manifest_file, 'r') as f:
                for line in f:
                    # Manifest format: package_name package_arch package_version
                    parts = line.strip().split()
                    if not parts:
                        continue
                    pkg = parts[0]
                    pkg_info = os.path.join(d.getVar('PKGDATA_DIR'),
                                            'runtime-reverse', pkg)
                    if os.path.exists(pkg_info):
                        pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
                        recipes.add(pkg_data["PN"])
                    else:
                        bb.warn(f"Package info not found for {pkg} at {pkg_info}")
            bb.note(f"Found {len(recipes)} recipes from manifest")
        else:
            # Fallback to image_list_installed_packages if manifest not available
            bb.warn("IMAGE_MANIFEST not found, falling back to image_list_installed_packages")
            for pkg in list(image_list_installed_packages(d)):
                pkg_info = os.path.join(d.getVar('PKGDATA_DIR'),
                                        'runtime-reverse', pkg)
                pkg_data = oe.packagedata.read_pkgdatafile(pkg_info)
                recipes.add(pkg_data["PN"])
    else:
        recipes = {pn for pn in os.listdir(cyclonedx_work_dir_root) if os.path.isdir(os.path.join(cyclonedx_work_dir_root, pn))}

    bb.note(f"Total recipes to process: {len(recipes)}")

    # Check which recipes have cyclonedx data available
    # Use CYCLONEDX_WORK_DIR_ROOT directly to avoid changing PN
    recipes_with_data = []
    for recipe in recipes:
        pn_list_filepath = os.path.join(cyclonedx_work_dir_root, recipe, "pn-list.json")
        if os.path.exists(pn_list_filepath):
            recipes_with_data.append(recipe)

    bb.note(f"Recipes with cyclonedx data: {len(recipes_with_data)} out of {len(recipes)}")
    if len(recipes_with_data) < len(recipes):
        missing = recipes - set(recipes_with_data)
        bb.warn(f"Missing cyclonedx data for {len(missing)} recipes. Examples: {list(missing)[:10]}")

    # Create a bom_ref_map for dependencies sanitarization
    # And an alias_map to retrieve real pkg name
    bom_ref_map = {}
    alias_map = {}

    # first loop to fill the dictionary
    for pkg in recipes:
        pn_list_filepath = os.path.join(cyclonedx_work_dir_root, pkg, "pn-list.json")

        if not os.path.exists(pn_list_filepath):
            continue

        pn_list = read_json(pn_list_filepath)
        for pn_pkg in pn_list["pkgs"]:
            bom_ref_map[pn_pkg["name"]]=pn_pkg
            alias_map[pkg]=pn_pkg["name"]

    cpe_dedup_map = {}
    for pkg in sorted(recipes):  # stable CPE-dedup winner across builds
        pn_list_filepath = os.path.join(cyclonedx_work_dir_root, pkg, "pn-list.json")

        if not os.path.exists(pn_list_filepath):
            continue

        pn_list = read_json(pn_list_filepath)

        for pn_pkg in pn_list["pkgs"]:
            # Avoid multiple pkgs referencing the same cpe
            for sbom_pkg in sbom["components"]:
                if pn_pkg["cpe"] == sbom_pkg["cpe"]:
                    # Cross-recipe CPE duplicate: this recipe's VEX entries still reference
                    # the skipped component, so record the redirect or they dangle.
                    cpe_dedup_map.setdefault(pn_pkg["bom-ref"], sbom_pkg["bom-ref"])
                    break
            else:
                sbom["components"].append(pn_pkg)
        for pn_cve in pn_list["cves"]:
            pn_cve["affects"][0]["ref"] = pn_cve["affects"][0]["ref"].replace(
                d.getVar('CYCLONEDX_SBOM_SERIAL_PLACEHOLDER'), sbom_serial_number)
            vex["vulnerabilities"].append(pn_cve)

        # Add dependencies
        if deps := pn_list.get("dependencies"):
            pn_list["dependencies"] = []

            for dep_entry in deps:
                resolved_depends = []

                for depends in dep_entry["dependsOn"]:
                    if resolved_ref := resolve_dependency_ref(depends, bom_ref_map, alias_map):
                        if resolved_ref not in resolved_depends:
                            resolved_depends.append(resolved_ref)

                            # Add component to isolate file
                            if ((depends in alias_map) and (alias_map[depends] in bom_ref_map)):
                                comp = bom_ref_map[alias_map[depends]]
                                if comp not in pn_list["pkgs"] :
                                    pn_list["pkgs"].append(comp)
                if resolved_depends :
                    updated_entry = {"ref": dep_entry["ref"], "dependsOn": resolved_depends}
                    pn_list["dependencies"].append(updated_entry)

                    if updated_entry not in sbom["dependencies"]:
                        sbom["dependencies"].append(updated_entry)

            write_json(pn_list_filepath, pn_list)

    # nnounce: fold in per-recipe pre-resolved CycloneDX fragments (e.g. Rust crate
    # trees injected by cyclonedx-cargo.bbclass under cargo_components /
    # cargo_dependencies). They carry their own bom-refs/purls and dependency edges,
    # so append them verbatim instead of running them through the CPE-dedup and
    # recipe-name dependency remap used for Yocto packages above.
    seen_refs = {c.get("bom-ref") for c in sbom["components"] if c.get("bom-ref")}
    for pkg in recipes:
        pn_list_filepath = os.path.join(cyclonedx_work_dir_root, pkg, "pn-list.json")
        if not os.path.exists(pn_list_filepath):
            continue
        extra = read_json(pn_list_filepath)
        for comp in extra.get("cargo_components", []):
            ref = comp.get("bom-ref") or comp.get("purl")
            if ref and ref in seen_refs:
                continue
            if ref:
                seen_refs.add(ref)
            sbom["components"].append(comp)
        for dep in extra.get("cargo_dependencies", []):
            if dep not in sbom["dependencies"]:
                sbom["dependencies"].append(dep)

    export_sbom_path = d.getVar("CYCLONEDX_EXPORT_SBOM")
    export_vex_path = d.getVar("CYCLONEDX_EXPORT_VEX")
    bb.note(f"Writing SBOM to: {export_sbom_path}")
    bb.note(f"Writing VEX to: {export_vex_path}")

    # Ensure the directory exists
    import os
    os.makedirs(os.path.dirname(export_sbom_path), exist_ok=True)

    import json
    # Redirect VEX affects at deduplicated components to the canonical bom-ref and
    # merge entries that now share an id (union of affects).
    merged_vulns = {}
    for vuln in vex["vulnerabilities"]:
        affects = []
        for affect in vuln.get("affects", []):
            prefix, sep, frag = affect.get("ref", "").partition("#")  # bom-refs may contain '#'
            seen = set()
            while sep and frag in cpe_dedup_map and frag not in seen:
                seen.add(frag)
                frag = cpe_dedup_map[frag]
            if sep:
                affect = dict(affect, ref=f"{prefix}#{frag}")
            if affect not in affects:
                affects.append(affect)
        vuln["affects"] = affects
        # Merge only when the analysis matches; differing verdicts stay separate entries.
        key = (vuln["id"], json.dumps(vuln.get("analysis", {}), sort_keys=True))
        existing = merged_vulns.get(key)
        if existing is None:
            merged_vulns[key] = vuln
        else:
            existing["affects"].extend(a for a in affects if a not in existing["affects"])
    vex["vulnerabilities"] = list(merged_vulns.values())

    write_json(export_sbom_path, sbom)
    write_json(export_vex_path, vex)
}

# For image recipes, add do_deploy_cyclonedx as a proper task to ensure sstate dependencies work
python __anonymous() {
    import bb
    # Check if this is an image recipe
    if bb.data.inherits_class('image', d):
        # Add as a proper task for images, runs after do_rootfs to access IMAGE_MANIFEST
        bb.build.addtask('do_deploy_cyclonedx', 'do_build', 'do_rootfs', d)
        # This task depends on having all recipe data available from do_populate_cyclonedx
        d.setVarFlag('do_deploy_cyclonedx', 'recrdeptask', 'do_populate_cyclonedx')
        d.setVarFlag('do_deploy_cyclonedx', 'cleandirs', d.getVar('CYCLONEDX_EXPORT_DIR'))
        # Force do_rootfs to wait for do_populate_cyclonedx from all runtime dependencies
        d.appendVarFlag('do_rootfs', 'recrdeptask', ' do_populate_cyclonedx')
}
