<!-- changelog: none -->

Move the SLH verifier identity command's stdout lint allowance onto its conditional
block so the compiler applies it without an unused-attribute warning. Runtime
behavior is unchanged.
