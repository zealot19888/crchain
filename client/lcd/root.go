package lcd

import (
	//"bufio"
	"bytes"
	"errors"
	//"cosmos-sdk/client/input"
	"fmt"
	"github.com/cosmos/cosmos-sdk/crypto"
	"github.com/cosmos/cosmos-sdk/crypto/keys"
	"github.com/tendermint/tendermint/crypto/multisig"
	"github.com/tendermint/tendermint/libs/cli"
	//"io"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/gorilla/mux"
	"github.com/rakyll/statik/fs"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tendermint/tendermint/libs/log"
	rpcserver "github.com/tendermint/tendermint/rpc/lib/server"

	"github.com/cosmos/cosmos-sdk/client/context"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/input"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/server"

	// unnamed import of statik for swagger UI support
	_ "github.com/cosmos/cosmos-sdk/client/lcd/statik"
)

type WalletRestConfig struct {
}

const (
	flagInteractive = "interactive"
	flagRecover     = "recover"
	flagNoBackup    = "no-backup"
	flagDryRun      = "dry-run"
	flagAccount     = "account"
	flagIndex       = "index"
	flagMultisig    = "multisig"
	flagNoSort      = "nosort"

	// DefaultKeyPass contains the default key password for genesis transactions
	DefaultKeyPass = "12345678"
)

// RestServer represents the Light Client Rest server
type RestServer struct {
	Mux    *mux.Router
	CliCtx context.CLIContext

	log      log.Logger
	listener net.Listener
}

// NewRestServer creates a new rest server instance
func NewRestServer(cdc *codec.Codec) *RestServer {
	r := mux.NewRouter()
	cliCtx := context.NewCLIContext().WithCodec(cdc)
	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout)).With("module", "rest-server")

	return &RestServer{
		Mux:    r,
		CliCtx: cliCtx,
		log:    logger,
	}
}

// Start starts the rest server
func (rs *RestServer) Start(listenAddr string, maxOpen int, readTimeout, writeTimeout uint) (err error) {
	server.TrapSignal(func() {
		err := rs.listener.Close()
		rs.log.Error("error closing listener", "err", err)
	})

	cfg := rpcserver.DefaultConfig()
	cfg.MaxOpenConnections = maxOpen
	cfg.ReadTimeout = time.Duration(readTimeout) * time.Second
	cfg.WriteTimeout = time.Duration(writeTimeout) * time.Second

	rs.listener, err = rpcserver.Listen(listenAddr, cfg)
	if err != nil {
		return
	}
	rs.log.Info(
		fmt.Sprintf(
			"Starting application REST service (chain-id: %q)...",
			viper.GetString(flags.FlagChainID),
		),
	)

	return rpcserver.StartHTTPServer(rs.listener, rs.Mux, rs.log, cfg)
}

// ServeCommand will start the application REST service as a blocking process. It
// takes a codec to create a RestServer object and a function to register all
// necessary routes.
func ServeCommand(cdc *codec.Codec, registerRoutesFn func(*RestServer)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rest-server",
		Short: "Start LCD (light-client daemon), a local REST server",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			rs := NewRestServer(cdc)

			registerRoutesFn(rs)
			rs.registerSwaggerUI()

			// Start the rest server and return error if one exists
			err = rs.Start(
				viper.GetString(flags.FlagListenAddr),
				viper.GetInt(flags.FlagMaxOpenConnections),
				uint(viper.GetInt(flags.FlagRPCReadTimeout)),
				uint(viper.GetInt(flags.FlagRPCWriteTimeout)),
			)

			return err
		},
	}

	return flags.RegisterRestServerFlags(cmd)
}

func (rs *RestServer) registerSwaggerUI() {
	statikFS, err := fs.New()
	if err != nil {
		panic(err)
	}
	staticServer := http.FileServer(statikFS)
	rs.Mux.PathPrefix("/swagger-ui/").Handler(http.StripPrefix("/swagger-ui/", staticServer))
}

func (rs *RestServer) CliWalletRoutes(cliCtx context.CLIContext, r *mux.Router, storeName string) {
	var config WalletRestConfig
	viper.Set("flagMultisig", nil)
	viper.Set("flagMultiSigThreshold", 1)
	viper.Set("flagNoSort", false)
	viper.Set("FlagPublicKey", "")
	viper.Set("flagInteractive", false)
	viper.Set(flags.FlagUseLedger, false)
	viper.Set("flagRecover", false)
	viper.Set("flagNoBackup", false)
	viper.Set("flagDryRun", false)
	viper.Set("flagAccount", 0)
	viper.Set("flagIndex", 0)
	viper.Set(flags.FlagIndentResponse, false)
	viper.Unmarshal(&config)
	r.HandleFunc(
		"/auth/createwallet", CliWalleCreateRequestHandlerFn(cliCtx),
	).Methods("GET").Queries("psword", "{psword:[a-zA-Z0-9]+}", "name", "{name:[a-zA-Z0-9]+}")
}

func CliWalleCreateRequestHandlerFn(cliCtx context.CLIContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fmt.Println("Vars:", vars["psword"])
		runAddCmd(w, r, vars)
	}
}

func getKeybase(transient bool, buf map[string]string) (keys.Keybase, error) {
	if transient {
		return keys.NewInMemory(), nil
	}

	return NewKeyringFromHomeHttp(buf)
}

func runAddCmd(w http.ResponseWriter, r *http.Request, datas map[string]string) error {
	// 读取commad 命令的字符串
	kb, err := getKeybase(viper.GetBool(flagDryRun), datas)
	if err != nil {
		return err
	}

	return RunAddCmd(kb, datas)
}

/*
input
	- bip39 mnemonic
	- bip39 passphrase
	- bip44 path
	- local encryption password
output
	- armor encrypted private key (saved to file)
*/
func RunAddCmd(kb keys.Keybase, inBuf map[string]string) error {
	var err error

	name := inBuf["name"]

	interactive := viper.GetBool(flagInteractive)
	showMnemonic := !viper.GetBool(flagNoBackup)

	if !viper.GetBool(flagDryRun) {
		_, err = kb.Get(name)
		if err == nil {
			// account exists, ask for user confirmation
			response, err2 := input.GetConfirmation(fmt.Sprintf("override the existing name %s", name), inBuf)
			if err2 != nil {
				return err2
			}
			if !response {
				return errors.New("aborted")
			}
		}

		multisigKeys := viper.GetStringSlice(flagMultisig)
		if len(multisigKeys) != 0 {
			var pks []crypto.PubKey

			multisigThreshold := viper.GetInt(flagMultiSigThreshold)
			if err := validateMultisigThreshold(multisigThreshold, len(multisigKeys)); err != nil {
				return err
			}

			for _, keyname := range multisigKeys {
				k, err := kb.Get(keyname)
				if err != nil {
					return err
				}
				pks = append(pks, k.GetPubKey())
			}

			// Handle --nosort
			if !viper.GetBool(flagNoSort) {
				sort.Slice(pks, func(i, j int) bool {
					return bytes.Compare(pks[i].Address(), pks[j].Address()) < 0
				})
			}

			pk := multisig.NewPubKeyMultisigThreshold(multisigThreshold, pks)
			if _, err := kb.CreateMulti(name, pk); err != nil {
				return err
			}

			cmd.PrintErrf("Key %q saved to disk.\n", name)
			return nil
		}
	}

	if viper.GetString(FlagPublicKey) != "" {
		pk, err := sdk.GetPubKeyFromBech32(sdk.Bech32PubKeyTypeAccPub, viper.GetString(FlagPublicKey))
		if err != nil {
			return err
		}
		_, err = kb.CreateOffline(name, pk)
		if err != nil {
			return err
		}
		return nil
	}

	account := uint32(viper.GetInt(flagAccount))
	index := uint32(viper.GetInt(flagIndex))

	// If we're using ledger, only thing we need is the path and the bech32 prefix.
	if viper.GetBool(flags.FlagUseLedger) {
		bech32PrefixAccAddr := sdk.GetConfig().GetBech32AccountAddrPrefix()
		info, err := kb.CreateLedger(name, keys.Secp256k1, bech32PrefixAccAddr, account, index)
		if err != nil {
			return err
		}

		return printCreate(cmd, info, false, "")
	}

	// Get bip39 mnemonic
	var mnemonic string
	var bip39Passphrase string

	if interactive || viper.GetBool(flagRecover) {
		bip39Message := "Enter your bip39 mnemonic"
		if !viper.GetBool(flagRecover) {
			bip39Message = "Enter your bip39 mnemonic, or hit enter to generate one."
		}

		mnemonic, err = input.GetString(bip39Message, inBuf)
		if err != nil {
			return err
		}

		if !bip39.IsMnemonicValid(mnemonic) {
			return errors.New("invalid mnemonic")
		}
	}

	if len(mnemonic) == 0 {
		// read entropy seed straight from crypto.Rand and convert to mnemonic
		entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
		if err != nil {
			return err
		}

		mnemonic, err = bip39.NewMnemonic(entropySeed)
		if err != nil {
			return err
		}
	}

	// override bip39 passphrase
	if interactive {
		bip39Passphrase, err = input.GetString(
			"Enter your bip39 passphrase. This is combined with the mnemonic to derive the seed. "+
				"Most users should just hit enter to use the default, \"\"", inBuf)
		if err != nil {
			return err
		}

		// if they use one, make them re-enter it
		if len(bip39Passphrase) != 0 {
			p2, err := input.GetString("Repeat the passphrase:", inBuf)
			if err != nil {
				return err
			}

			if bip39Passphrase != p2 {
				return errors.New("passphrases don't match")
			}
		}
	}

	info, err := kb.CreateAccount(name, mnemonic, bip39Passphrase, DefaultKeyPass, account, index)
	if err != nil {
		return err
	}

	// Recover key from seed passphrase
	if viper.GetBool(flagRecover) {
		// Hide mnemonic from output
		showMnemonic = false
		mnemonic = ""
	}

	return printCreate(cmd, info, showMnemonic, mnemonic)
}

func printCreate(cmd *cobra.Command, info keys.Info, showMnemonic bool, mnemonic string) error {
	output := viper.Get(cli.OutputFlag)

	switch output {
	case OutputFormatText:
		cmd.PrintErrln()
		printKeyInfo(info, keys.Bech32KeyOutput)

		// print mnemonic unless requested not to.
		if showMnemonic {
			cmd.PrintErrln("\n**Important** write this mnemonic phrase in a safe place.")
			cmd.PrintErrln("It is the only way to recover your account if you ever forget your password.")
			cmd.PrintErrln("")
			cmd.PrintErrln(mnemonic)
		}
	case OutputFormatJSON:
		out, err := keys.Bech32KeyOutput(info)
		if err != nil {
			return err
		}

		if showMnemonic {
			out.Mnemonic = mnemonic
		}

		var jsonString []byte
		if viper.GetBool(flags.FlagIndentResponse) {
			jsonString, err = KeysCdc.MarshalJSONIndent(out, "", "  ")
		} else {
			jsonString, err = KeysCdc.MarshalJSON(out)
		}

		if err != nil {
			return err
		}
		cmd.PrintErrln(string(jsonString))
	default:
		return fmt.Errorf("invalid output format %s", output)
	}

	return nil
}
