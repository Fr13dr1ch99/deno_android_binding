use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

pub type NativeString = *const c_char;
pub type ExternLogCallbackType = Option<extern "C" fn(u32, NativeString)>;
use async_ffi::{FfiFuture, FutureExt};
use futures::executor::block_on;

use deno_runtime::deno_core::anyhow::Context;
use deno_runtime::deno_core::error::AnyError;
use deno_runtime::deno_broadcast_channel::InMemoryBroadcastChannel;
use deno_runtime::deno_web::BlobStore;
use deno_runtime::permissions::PermissionsContainer;

use deno_runtime::worker::MainWorker;
use deno_runtime::worker::WorkerOptions;
use deno_runtime::WorkerLogLevel;
use deno_runtime::deno_fs;
use deno_runtime::deno_core::JsRuntime;


//use deno_runtime::deno_core::*;


use deno_runtime::BootstrapOptions;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use deno_runtime::web_worker::SendableWebWorkerHandle;
use deno_runtime::web_worker::WebWorker;

/* JAVA */
use jni::JNIEnv;
use std::{sync::mpsc, thread, time::Duration};
use jni::objects::{GlobalRef, JClass, JString};
use jni::objects::JByteArray;
use jni::sys::{jint, jlong};

use url::ParseError;
use url::Url;
use std::panic;


use futures::executor::LocalPool;
use futures::task::LocalSpawnExt;

#[allow(dead_code)]
fn main() {
	let _ = simple_logging::log_to_file("./init.log", log::LevelFilter::Info);
	log::info!("INIT THREAD");
	let path = "./test1.js";
	let worker = initWorker(path);
	let mut local_pool = LocalPool::new();
	let spawner = local_pool.spawner();
	spawner.spawn_local(async move {
		runjs(path, "./".to_string(), worker).await;
	});

	local_pool.run();

	log::info!("END SYSTEM");
}

fn get_error_class_name(e: &AnyError) -> &'static str {
	deno_runtime::errors::get_error_class_name(e).unwrap_or("Error")
}


fn initWorker(filepath: &str) -> JsRuntime {
	panic::set_hook(Box::new(|panic_info| {
		// Hier kannst du das Panic-Info protokollieren oder andere Aktionen durchführen
		log::info!("PANIC: {:?}", panic_info);
	}));

	let current_dir = std::env::current_dir().unwrap();
	let main_module = deno_runtime::deno_core::resolve_path(&filepath, &current_dir);
	let main_module_clone = main_module.clone();
	if let Err(ref err) = main_module_clone {
		log::info!("ERROR: {:?}", err);
	}
	log::info!("CREATE PERMISSION CONTAINER");
	let permissions = PermissionsContainer::allow_all();
	log::info!("CREATE WORKER OPTIONS");
	let options = WorkerOptions {..Default::default()};
	log::info!("INIT NEW MAIN WORKER {}", filepath);
	let mut js_runtime = deno_runtime::deno_core::JsRuntime::new(deno_runtime::deno_core::RuntimeOptions {
		..Default::default()
	});

	/*let bootstrap_options = options.bootstrap.clone();
	log::info!("1");
  let mut worker = MainWorker::from_options(main_module_clone.unwrap(), permissions, options);
	log::info!("2");
  worker.bootstrap(bootstrap_options);*/
	/*let worker = MainWorker::bootstrap_from_options(
		main_module_clone.unwrap(),
		permissions,
		workeroptions
	);*/
	log::info!("DONE");
	return js_runtime;
}


#[no_mangle]
async fn runjs(filepath: &str, logdir: String, mut runtime: JsRuntime) -> Result<(), AnyError> {
	//tokio::runtime::Runtime::new().unwrap().shutdown_background();
	let _ = simple_logging::log_to_file(logdir.to_owned() + "/execution.log", log::LevelFilter::Info);
	log::info!("INIT RUNJS");
	log::info!("LOAD PATH {}", filepath);
	let current_dir = std::env::current_dir().unwrap();
	let main_module = deno_runtime::deno_core::resolve_path(&filepath, &current_dir).unwrap();
	
	let mod_id = runtime.load_main_module(&main_module, None).await?;
  let result = runtime.mod_evaluate(mod_id);
  runtime.run_event_loop(false).await?;
  result.await?;


	/*log::info!("EXECUTE");
		let result = worker.execute_main_module(&main_module).await;
		if let Err(err) = result {
			log::info!("execute_mod err {err:?}");
		}
		if let Err(e) = worker.run_event_loop(false).await {
			log::info!("Future got unexpected error: {e:?}");
		}*/
	log::info!("execute_main_module end");
	Ok(())
}

/// Expose the JNI interface for android below
#[cfg(target_os="android")]
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern fn Java_com_vision_xcelerator_NativeWrapper_greeting<'local>(
	mut env: JNIEnv<'local>,
	_: JClass<'local>,
	java_pattern: JString<'local>
) -> JString<'local> {
	let text: String = env.get_string(&java_pattern).expect("Couldn't get java string!").into();
	let output = env.new_string(format!("Hello {}!", text)).expect("Couldn't create java string!");
 	output
}

#[cfg(target_os="android")]
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn Java_com_vision_xcelerator_NativeWrapper_runjs<'local>(
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	java_file: JString<'local>,
	java_logdir: JString<'local>
) -> JString<'local> {
	let filepath: String = env.get_string(&java_file).expect("Couldn't get java string!").into();
	let logdir: String = env.get_string(&java_logdir).expect("Couldn't get java string!").into();

	let _ = simple_logging::log_to_file(logdir.to_owned() + "/init.log", log::LevelFilter::Info);

	log::info!("INIT THREAD");
	let worker = initWorker(&filepath);
	log::info!("INIT RUNTIME");
	tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async move {
            runjs(&filepath, logdir, worker).await;
        });


	log::info!("END SYSTEM");
	let output = env.new_string(format!("DONE!")).expect("Couldn't create java string!");
 	output
}

