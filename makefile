BUILD_DIR = build


TARJEI = kernel-attacks-through-user-mode-callbacks


tarjei:
	gitbook pdf ${TARJEI} ${BUILD_DIR}/${TARJEI}.pdf
