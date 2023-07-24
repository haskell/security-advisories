(builtins.getFlake ("git+file://" + toString ./.)).devShell.${builtins.currentSystem}
