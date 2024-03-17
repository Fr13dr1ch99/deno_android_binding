







use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

use deno_runtime::deno_cache::CreateCache;
use deno_runtime::deno_cache::SqliteBackedCache;
use deno_runtime::deno_core::ascii_str;
use deno_runtime::deno_core::error::JsError;
use deno_runtime::deno_core::merge_op_metrics;
use deno_runtime::deno_core::v8;
use deno_runtime::deno_core::CompiledWasmModuleStore;
use deno_runtime::deno_core::Extension;
use deno_runtime::deno_core::FeatureChecker;
use deno_runtime::deno_core::FsModuleLoader;
use deno_runtime::deno_core::GetErrorClassFn;
use deno_runtime::deno_core::JsRuntime;
use deno_runtime::deno_core::LocalInspectorSession;
use deno_runtime::deno_core::ModuleCodeString;
use deno_runtime::deno_core::ModuleId;
use deno_runtime::deno_core::ModuleLoader;
use deno_runtime::deno_core::ModuleSpecifier;
use deno_runtime::deno_core::OpMetricsFactoryFn;
use deno_runtime::deno_core::OpMetricsSummaryTracker;
use deno_runtime::deno_core::PollEventLoopOptions;
use deno_runtime::deno_core::RuntimeOptions;
use deno_runtime::deno_core::SharedArrayBufferStore;
use deno_runtime::deno_core::Snapshot;
use deno_runtime::deno_core::SourceMapGetter;
use deno_runtime::deno_cron::local::LocalCronHandler;
use deno_runtime::deno_fs::FileSystem;
use deno_runtime::deno_http::DefaultHttpPropertyExtractor;
use deno_runtime::deno_io::Stdio;
use deno_runtime::deno_kv::dynamic::MultiBackendDbHandler;
use deno_runtime::deno_tls::RootCertStoreProvider;
use deno_runtime::ops;



use deno_runtime::inspector_server::InspectorServer;




pub fn runtime_from_options(
	main_module: ModuleSpecifier,
	permissions: PermissionsContainer,
	mut options: WorkerOptions,
) -> MainWorker {
	/*deno_runtime::deno_core::extension!(deno_permissions_worker,
		options = {
			permissions: PermissionsContainer,
			enable_testing_features: bool,
		},
		state = |state, options| {
			state.put::<PermissionsContainer>(options.permissions);
			state.put(ops::TestingFeaturesEnabled(options.enable_testing_features));
		},
	);*/

	// Get our op metrics
	let (op_summary_metrics, op_metrics_factory_fn) = create_op_metrics(
		options.bootstrap.enable_op_summary_metrics,
		options.strace_ops,
	);

	// Permissions: many ops depend on this
	let enable_testing_features = options.bootstrap.enable_testing_features;
	let create_cache = options.cache_storage_dir.map(|storage_dir| {
		let create_cache_fn = move || SqliteBackedCache::new(storage_dir.clone());
		CreateCache(Arc::new(create_cache_fn))
	});

	// NOTE(bartlomieju): ordering is important here, keep it in sync with
	// `runtime/web_worker.rs` and `runtime/snapshot.rs`!
	let mut extensions = vec![
		// Web APIs
		deno_runtime::deno_webidl::deno_webidl::init_ops_and_esm(),
		deno_runtime::deno_console::deno_console::init_ops_and_esm(),
		deno_runtime::deno_url::deno_url::init_ops_and_esm(),
		deno_runtime::deno_web::deno_web::init_ops_and_esm::<PermissionsContainer>(
			options.blob_store.clone(),
			options.bootstrap.location.clone(),
		),
		deno_runtime::deno_fetch::deno_fetch::init_ops_and_esm::<PermissionsContainer>(
			deno_runtime::deno_fetch::Options {
				user_agent: options.bootstrap.user_agent.clone(),
				root_cert_store_provider: options.root_cert_store_provider.clone(),
				unsafely_ignore_certificate_errors: options
					.unsafely_ignore_certificate_errors
					.clone(),
				file_fetch_handler: Rc::new(deno_runtime::deno_fetch::FsFetchHandler),
				..Default::default()
			},
		),
		deno_runtime::deno_cache::deno_cache::init_ops_and_esm::<SqliteBackedCache>(
			create_cache,
		),
		deno_runtime::deno_websocket::deno_websocket::init_ops_and_esm::<PermissionsContainer>(
			options.bootstrap.user_agent.clone(),
			options.root_cert_store_provider.clone(),
			options.unsafely_ignore_certificate_errors.clone(),
		),
		deno_runtime::deno_webstorage::deno_webstorage::init_ops_and_esm(
			options.origin_storage_dir.clone(),
		),
		deno_runtime::deno_crypto::deno_crypto::init_ops_and_esm(options.seed),
		deno_runtime::deno_broadcast_channel::deno_broadcast_channel::init_ops_and_esm(
			options.broadcast_channel.clone(),
		),
		deno_runtime::deno_net::deno_net::init_ops_and_esm::<PermissionsContainer>(
			options.root_cert_store_provider.clone(),
			options.unsafely_ignore_certificate_errors.clone(),
		),
		deno_runtime::deno_tls::deno_tls::init_ops_and_esm(),
		deno_runtime::deno_kv::deno_kv::init_ops_and_esm(
			MultiBackendDbHandler::remote_or_sqlite::<PermissionsContainer>(
				options.origin_storage_dir.clone(),
				options.seed,
				deno_runtime::deno_kv::remote::HttpOptions {
					user_agent: options.bootstrap.user_agent.clone(),
					root_cert_store_provider: options.root_cert_store_provider.clone(),
					unsafely_ignore_certificate_errors: options
						.unsafely_ignore_certificate_errors
						.clone(),
					client_cert_chain_and_key: None,
					proxy: None,
				},
			),
		),
		deno_runtime::deno_cron::deno_cron::init_ops_and_esm(LocalCronHandler::new()),
		deno_runtime::deno_napi::deno_napi::init_ops_and_esm::<PermissionsContainer>(),
		deno_runtime::deno_http::deno_http::init_ops_and_esm::<DefaultHttpPropertyExtractor>(),
		deno_runtime::deno_io::deno_io::init_ops_and_esm(Some(options.stdio)),
		deno_runtime::deno_fs::deno_fs::init_ops_and_esm::<PermissionsContainer>(
			options.fs.clone(),
		),
		deno_runtime::deno_node::deno_node::init_ops_and_esm::<PermissionsContainer>(
			options.npm_resolver,
			options.fs,
		),
		// Ops from this crate
		ops::runtime::deno_runtime::init_ops_and_esm(main_module.clone()),
		ops::worker_host::deno_worker_host::init_ops_and_esm(
			options.create_web_worker_cb.clone(),
			options.format_js_error_fn.clone(),
		),
		ops::fs_events::deno_fs_events::init_ops_and_esm(),
		ops::os::deno_os::init_ops_and_esm(Default::default()),
		ops::permissions::deno_permissions::init_ops_and_esm(),
		ops::process::deno_process::init_ops_and_esm(),
		ops::signal::deno_signal::init_ops_and_esm(),
		ops::tty::deno_tty::init_ops_and_esm(),
		ops::http::deno_http_runtime::init_ops_and_esm(),
		ops::bootstrap::deno_bootstrap::init_ops_and_esm(
			if options.startup_snapshot.is_some() {
				None
			} else {
				Some(Default::default())
			},
		),
		/*deno_runtime::deno_permissions_worker::init_ops_and_esm(
			permissions,
			enable_testing_features,
		),*/
		//runtime::init_ops_and_esm(),
		// NOTE(bartlomieju): this is done, just so that ops from this extension
		// are available and importing them in `99_main.js` doesn't cause an
		// error because they're not defined. Trying to use these ops in non-worker
		// context will cause a panic.
		ops::web_worker::deno_web_worker::init_ops_and_esm().disable(),
	];


	#[cfg(__runtime_js_sources)]
	assert!(cfg!(not(feature = "only_snapshotted_js_sources")), "'__runtime_js_sources' is incompatible with 'only_snapshotted_js_sources'.");

	for extension in &mut extensions {
		if options.startup_snapshot.is_some() {
			extension.js_files = std::borrow::Cow::Borrowed(&[]);
			extension.esm_files = std::borrow::Cow::Borrowed(&[]);
			extension.esm_entry_point = None;
		}
		#[cfg(not(feature = "only_snapshotted_js_sources"))]
		{
			use maybe_transpile_source;
			for source in extension.esm_files.to_mut() {
				maybe_transpile_source(source).unwrap();
			}
			for source in extension.js_files.to_mut() {
				maybe_transpile_source(source).unwrap();
			}
		}
	}

	extensions.extend(std::mem::take(&mut options.extensions));

	#[cfg(feature = "only_snapshotted_js_sources")]
	options.startup_snapshot.as_ref().expect("A user snapshot was not provided, even though 'only_snapshotted_js_sources' is used.");

	let has_notified_of_inspector_disconnect = AtomicBool::new(false);
	let wait_for_inspector_disconnect_callback = Box::new(move || {
		if !has_notified_of_inspector_disconnect
			.swap(true, std::sync::atomic::Ordering::SeqCst)
		{
			println!("Program finished. Waiting for inspector to disconnect to exit the process...");
		}
	});

	let mut js_runtime = JsRuntime::new(RuntimeOptions {
		module_loader: Some(options.module_loader.clone()),
		startup_snapshot: options.startup_snapshot,
		create_params: options.create_params,
		source_map_getter: options.source_map_getter,
		skip_op_registration: options.skip_op_registration,
		get_error_class_fn: options.get_error_class_fn,
		shared_array_buffer_store: options.shared_array_buffer_store.clone(),
		compiled_wasm_module_store: options.compiled_wasm_module_store.clone(),
		extensions,
		inspector: options.maybe_inspector_server.is_some(),
		is_main: true,
		feature_checker: Some(options.feature_checker.clone()),
		op_metrics_factory_fn,
		wait_for_inspector_disconnect_callback: Some(
			wait_for_inspector_disconnect_callback,
		),
		import_meta_resolve_callback: Some(Box::new(
			import_meta_resolve_callback,
		)),
		validate_import_attributes_cb: Some(Box::new(
			validate_import_attributes_callback,
		)),
		..Default::default()
	});

	if let Some(op_summary_metrics) = op_summary_metrics {
		js_runtime.op_state().borrow_mut().put(op_summary_metrics);
	}

	if let Some(server) = options.maybe_inspector_server.clone() {
		server.register_inspector(
			main_module.to_string(),
			&mut js_runtime,
			options.should_break_on_first_statement
				|| options.should_wait_for_inspector_session,
		);

		// Put inspector handle into the op state so we can put a breakpoint when
		// executing a CJS entrypoint.
		let op_state = js_runtime.op_state();
		let inspector = js_runtime.inspector();
		op_state.borrow_mut().put(inspector);
	}
	let bootstrap_fn_global = {
		let context = js_runtime.main_context();
		let scope = &mut js_runtime.handle_scope();
		let context_local = v8::Local::new(scope, context);
		let global_obj = context_local.global(scope);
		let bootstrap_str =
			v8::String::new_external_onebyte_static(scope, b"bootstrap").unwrap();
		let bootstrap_ns: v8::Local<v8::Object> = global_obj
			.get(scope, bootstrap_str.into())
			.unwrap()
			.try_into()
			.unwrap();
		let main_runtime_str =
			v8::String::new_external_onebyte_static(scope, b"mainRuntime").unwrap();
		let bootstrap_fn =
			bootstrap_ns.get(scope, main_runtime_str.into()).unwrap();
		let bootstrap_fn =
			v8::Local::<v8::Function>::try_from(bootstrap_fn).unwrap();
		v8::Global::new(scope, bootstrap_fn)
	};

	MainWorker {
		js_runtime,
		should_break_on_first_statement: options.should_break_on_first_statement,
		should_wait_for_inspector_session: options
			.should_wait_for_inspector_session,
		Default::default(),
		bootstrap_fn_global: Some(bootstrap_fn_global),
	}
}






















/*
#[derive(Clone, Default)]
pub struct ExitCode(Arc<AtomicI32>);

impl ExitCode {
  pub fn get(&self) -> i32 {
    self.0.load(Relaxed)
  }

  pub fn set(&mut self, code: i32) {
    self.0.store(code, Relaxed);
  }
}*/



pub fn import_meta_resolve_callback(
  loader: &dyn deno_runtime::deno_core::ModuleLoader,
  specifier: String,
  referrer: String,
) -> Result<ModuleSpecifier, AnyError> {
  loader.resolve(
    &specifier,
    &referrer,
    deno_runtime::deno_core::ResolutionKind::DynamicImport,
  )
}


// TODO(bartlomieju): temporary measurement until we start supporting more
// module types
pub fn validate_import_attributes_callback(
  scope: &mut v8::HandleScope,
  attributes: &HashMap<String, String>,
) {
  for (key, value) in attributes {
    let msg = if key != "type" {
      Some(format!("\"{key}\" attribute is not supported."))
    } else if value != "json" {
      Some(format!("\"{value}\" is not a valid module type."))
    } else {
      None
    };

    let Some(msg) = msg else {
      continue;
    };

    let message = v8::String::new(scope, &msg).unwrap();
    let exception = v8::Exception::type_error(scope, message);
    scope.throw_exception(exception);
    return;
  }
}




use deno_runtime::deno_core::ExtensionFileSource;
use deno_runtime::deno_core::ExtensionFileSourceCode;


pub fn maybe_transpile_source(
  source: &mut ExtensionFileSource,
) -> Result<(), AnyError> {
  // Always transpile `node:` built-in modules, since they might be TypeScript.
  let media_type = if source.specifier.starts_with("node:") {
    deno_ast::MediaType::TypeScript
  } else {
    deno_ast::MediaType::from_path(Path::new(&source.specifier))
  };

  match media_type {
    deno_ast::MediaType::TypeScript => {}
    deno_ast::MediaType::JavaScript => return Ok(()),
    deno_ast::MediaType::Mjs => return Ok(()),
    _ => panic!(
      "Unsupported media type for snapshotting {media_type:?} for file {}",
      source.specifier
    ),
  }
  let code = source.load()?;

  let parsed = deno_ast::parse_module(deno_ast::ParseParams {
    specifier: deno_runtime::deno_core::url::Url::parse(source.specifier).unwrap(),
    text_info: deno_ast::SourceTextInfo::from_string(code.as_str().to_owned()),
    media_type,
    capture_tokens: false,
    scope_analysis: false,
    maybe_syntax: None,
  })?;
  let transpiled_source = parsed.transpile(&deno_ast::EmitOptions {
    imports_not_used_as_values: deno_ast::ImportsNotUsedAsValues::Remove,
    inline_source_map: false,
    ..Default::default()
  })?;

  source.code =
    ExtensionFileSourceCode::Computed(transpiled_source.text.into());
  Ok(())
}




fn create_op_metrics(
  enable_op_summary_metrics: bool,
  strace_ops: Option<Vec<String>>,
) -> (
  Option<Rc<OpMetricsSummaryTracker>>,
  Option<OpMetricsFactoryFn>,
) {
  let mut op_summary_metrics = None;
  let mut op_metrics_factory_fn: Option<OpMetricsFactoryFn> = None;
  let now = Instant::now();
  let max_len: Rc<std::cell::Cell<usize>> = Default::default();
  if let Some(patterns) = strace_ops {
    /// Match an op name against a list of patterns
    fn matches_pattern(patterns: &[String], name: &str) -> bool {
      let mut found_match = false;
      let mut found_nomatch = false;
      for pattern in patterns.iter() {
        if let Some(pattern) = pattern.strip_prefix('-') {
          if name.contains(pattern) {
            return false;
          }
        } else if name.contains(pattern.as_str()) {
          found_match = true;
        } else {
          found_nomatch = true;
        }
      }

      found_match || !found_nomatch
    }

    op_metrics_factory_fn = Some(Box::new(move |_, _, decl| {
      // If we don't match a requested pattern, or we match a negative pattern, bail
      if !matches_pattern(&patterns, decl.name) {
        return None;
      }

      max_len.set(max_len.get().max(decl.name.len()));
      let max_len = max_len.clone();
      Some(Rc::new(
        move |op: &deno_runtime::deno_core::_ops::OpCtx, event, source| {
          eprintln!(
            "[{: >10.3}] {name:max_len$}: {event:?} {source:?}",
            now.elapsed().as_secs_f64(),
            name = op.decl().name,
            max_len = max_len.get()
          );
        },
      ))
    }));
  }

  if enable_op_summary_metrics {
    let summary = Rc::new(OpMetricsSummaryTracker::default());
    let summary_metrics = summary.clone().op_metrics_factory_fn(|_| true);
    op_metrics_factory_fn = Some(match op_metrics_factory_fn {
      Some(f) => merge_op_metrics(f, summary_metrics),
      None => summary_metrics,
    });
    op_summary_metrics = Some(summary);
  }

  (op_summary_metrics, op_metrics_factory_fn)
}





















