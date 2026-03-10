vim.keymap.set(
	"n",
	"<leader>cP",
	":botright 10split | term cloc Main/Frontend/src/*.js Main/Frontend/src/assets/scripts/*.js Main/Backend/*.py Main/Frontend/src/*.html Main/Frontend/src/*.js Main/Frontend/src/assets/scripts/scripts.js | grep Language -A 10000 -B 1<CR>",
	{ desc = "LOC in the current project" }
)
