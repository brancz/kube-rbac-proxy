vm_prefix = File.basename(File.dirname(Dir.getwd)) + "_" + File.basename(Dir.getwd)

Vagrant.configure("2") do |config|
  config.vm.box = "bento/fedora-latest"

  config.vm.boot_timeout = 600  # Give VM more time to boot and get IP
  #config.vm.network "forwarded_port", guest: 3000, host: 3000, auto_correct: true

  config.vm.provider :libvirt do |libvirt|
    libvirt.default_prefix = vm_prefix
    libvirt.memory = 4096
    libvirt.cpus = 2
    libvirt.memorybacking :access, :mode => "shared"  # Required for virtiofs
  end

  config.vm.synced_folder ".", "/workspace", type: "virtiofs"

  # System packages (runs as root)
  config.vm.provision "shell", inline: <<-SHELL
    dnf update -y
    dnf install -y nodejs git ripgrep fd-find fish neovim tmux gcc make bat fzf zoxide
    curl -sS https://starship.rs/install.sh | sh -s -- -y
    chsh -s /usr/bin/fish vagrant
  SHELL

  # User setup (runs as vagrant)
  config.vm.provision "shell", privileged: false, inline: <<-'SHELL'
    curl -fsSL https://claude.ai/install.sh | bash

    mkdir -p ~/.config/fish
    starship preset catppuccin-powerline > ~/.config/starship.toml

    cat > ~/.config/fish/config.fish << 'FISHCONFIG'
set -gx EDITOR nvim
set -gx TERM xterm-256color

set -gx LANG en_US.UTF-8
set -gx LANGUAGE en_US.UTF-8

set -gx XDG_DATA_HOME $HOME/.local/share
set -gx XDG_CONFIG_HOME $HOME/.config
set -gx XDG_CACHE_HOME $HOME/.cache

# !! function to repeat last command
function bind_bang
    switch (commandline -t)[-1]
        case "!"
            commandline -t $history[1]
            commandline -f repaint
        case "*"
            commandline -i !
    end
end

function bind_dollar
    switch (commandline -t)[-1]
        case "!"
            commandline -t ""
            commandline -f history-token-search-backward
        case "*"
            commandline -i '$'
    end
end

if status is-interactive
    # Go
    set -gx GOPATH $HOME/go
    set -gx GOBIN $GOPATH/bin

    # PATH
    fish_add_path ~/.local/bin
    fish_add_path $GOBIN

    # Claude alias
    alias claude '~/.local/bin/claude --dangerously-skip-permissions'

    # Navigation aliases
    alias .. 'cd ..'
    alias ... 'cd ../..'
    alias .... 'cd ../../..'
    alias ..... 'cd ../../../..'
    alias cdtemp 'cd (mktemp -d)'

    # Git aliases
    alias g git
    alias ga 'git add'
    alias gaa 'git add --all'
    alias gco 'git checkout'
    alias gst 'git status'
    alias ggl 'git pull'
    alias gcsm 'git commit --gpg-sign --signoff --message'
    alias gcse 'git commit --gpg-sign --signoff --edit'
    alias gd 'git diff'
    alias gdpr 'git diff HEAD^'
    alias grb 'git rebase'
    alias grba 'git rebase --abort'
    alias grbc 'git rebase --continue'
    alias grbi 'git rebase -i'
    alias gr 'git remote'
    alias grv 'git remote --verbose'
    alias grh 'git reset'
    alias grhh 'git reset --hard'

    # General aliases
    alias please sudo
    alias v 'nvim .'
    alias n nvim
    alias vim nvim
    alias j z
    alias mkdir 'mkdir -p'

    # Tool aliases (bat, fzf)
    alias ff "fzf --preview 'bat --style=numbers --color=always {}'"

    # Tool completions
    if type -q kubectl
        kubectl completion fish | source
    end
    if type -q oc
        oc completion fish | source
    end
    if type -q gh
        gh completion -s fish | source
    end

    # Starship
    starship init fish | source

    # Zoxide
    zoxide init fish | source

    # FZF configuration
    set -gx FZF_DEFAULT_COMMAND "fd --hidden --strip-cwd-prefix --exclude .git"
    set -gx FZF_CTRL_T_COMMAND "$FZF_DEFAULT_COMMAND"
    set -gx FZF_ALT_C_COMMAND "fd --type=d --hidden --strip-cwd-prefix --exclude .git"
    set -gx FZF_CTRL_T_OPTS "--preview 'if test -d {}; ls --color=always {} | head -200; else bat -n --color=always --line-range :500 {}; end'"
    set -gx FZF_ALT_C_OPTS "--preview 'ls --color=always {} | head -200'"

    # Greeting
    set -U fish_greeting 'As-salamu alaykum - Peace be upon you'

    # Start in workspace and launch claude
    cd /workspace && claude --continue || claude
end
FISHCONFIG

    git clone https://github.com/LazyVim/starter ~/.config/nvim
    rm -rf ~/.config/nvim/.git
  SHELL
end
