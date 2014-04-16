/*
 *  Multi2Sim
 *  Copyright (C) 2007  Rafael Ubal Tena (raurte@gap.upv.es)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <m2skernel.h>
void push_into_queue(struct my_interrupts_queue *l,struct my_interrupt I){
	int i;
	for(i=0;i<l->end;i++){
		if(l->Queue[i].n > I.n){
			int j;
			for(j=l->end;j>i;j--){
				l->Queue[j] = l->Queue[j-1];
			}
			l->Queue[i] = I;
			l->end = l->end+1;
			return;
		}
	}
	l->Queue[l->end] = I;
	l->end = l->end+1;
	return;
}
void pop_outta_queue(struct my_interrupts_queue *l){
	int i;
	for(i=1;i<l->end;i++){
		l->Queue[i]=l->Queue[i-1];
	}
	l->end = l->end -1;
}
struct my_interrupt front_of_queue(struct my_interrupts_queue *l){
	return l->Queue[0];
}

/* Global Multi2Sim
 * Kernel Variable */
struct kernel_t *ke;

/* Initialization */

static uint64_t ke_init_time = 0;

void ke_init(void)
{
	uint32_t endian = 0x44332211;
	unsigned char *pendian = (unsigned char *) &endian;

	/* Endian check */
	if (pendian[0] != 0x11 || pendian[3] != 0x44)
		fatal("cannot run kernel on a big endian machine");
	
	isa_init();
	ke = calloc(1, sizeof(struct kernel_t));
	ke->current_pid = 1000;  /* Initial assigned pid */
	
	/* Initialize mutex for variables controlling calls to 'ke_process_events()' */
	pthread_mutex_init(&ke->process_events_mutex, NULL);

	/* Debug categories */
	isa_inst_debug_category = debug_new_category();
	isa_call_debug_category = debug_new_category();
	elf_debug_category = debug_new_category();
	ld_debug_category = debug_new_category();
	syscall_debug_category = debug_new_category();
	ctx_debug_category = debug_new_category();

	/* Initialize GPU kernel */
	gk_init();

	/* Record start time */
	INSTR_COUNTER = 1;
	Q.end=0;
	ke_init_time = ke_timer();
}


/* Finalization */
void ke_done(void)
{
	struct ctx_t *ctx;

	/* Finish all contexts */
	for (ctx = ke->context_list_head; ctx; ctx = ctx->context_next)
		if (!ctx_get_status(ctx, ctx_finished))
			ctx_finish(ctx, 0);

	/* Free contexts */
	while (ke->context_list_head)
		ctx_free(ke->context_list_head);
	
	/* Finalize GPU kernel */
	gk_done();

	/* End */
	free(ke);
	isa_done();
	syscall_summary();
}

/* Execute one instruction from each running context. */
void ke_run(void)
{
	struct ctx_t *ctx, *ctx_trav; 
	int flag = 0;
	
	
	/* Run an instruction from every running process */
	for (ctx = ke->running_list_head; ctx; ctx = ctx->running_next) {
		int i;
		//printf ("out - %p\n", ctx);

		for ( i = 0 ; i < ctx->instr_slice ; ++i){
			ctx_execute_inst(ctx);
			INSTR_COUNTER++;
			if(Q.end != 0){
				if(front_of_queue(&Q).n == INSTR_COUNTER){
				INSTR_COUNTER++;
				ctx = ctx_get(front_of_queue(&Q).pid);
				ctx_clear_status(ctx,ctx_suspended | ctx_read | ctx_write);
				ctx_set_status(ctx,ctx_running);
				pop_outta_queue(&Q);
				break;
				}
			}
		}

		if (ctx!=ke->running_list_head)
			break;
	}
	
	/* Free finished contexts */
	while (ke->finished_list_head)
		ctx_free(ke->finished_list_head);
	
	if(Q.end != 0){
		ctx = ctx_get(front_of_queue(&Q).pid);
		ctx_clear_status(ctx,ctx_suspended | ctx_read | ctx_write);
		ctx_set_status(ctx,ctx_running);
		pop_outta_queue(&Q);
	}
		
	/* Process list of suspended contexts */
	ke_process_events();

}


void ke_dump(FILE *f)
{
	struct ctx_t *ctx;
	int n = 0;
	ctx = ke->context_list_head;
	fprintf(f, "List of kernel contexts (arbitrary order):\n");
	while (ctx) {
		fprintf(f, "kernel context #%d:\n", n);
		ctx_dump(ctx, f);
		ctx = ctx->context_next;
		n++;
	}
}


#define LIST_INSERT_HEAD(name, ctx) { \
	assert(!ctx->name##_next && !ctx->name##_prev); \
	ctx->name##_next = ke->name##_list_head; \
	if (ctx->name##_next) ctx->name##_next->name##_prev = ctx; \
	ke->name##_list_head = ctx; \
	if (!ke->name##_list_tail) ke->name##_list_tail = ctx; \
	ke->name##_count++; \
	ke->name##_max = MAX(ke->name##_max, ke->name##_count); }

#define LIST_INSERT_TAIL(name, ctx) { \
	assert(!ctx->name##_next && !ctx->name##_prev); \
	ctx->name##_prev = ke->name##_list_tail; \
	if (ctx->name##_prev) ctx->name##_prev->name##_next = ctx; \
	ke->name##_list_tail = ctx; \
	if (!ke->name##_list_head) ke->name##_list_head = ctx; \
	ke->name##_count++; }

#define LIST_REMOVE(name, ctx) { \
	if (ctx == ke->name##_list_head) ke->name##_list_head = ke->name##_list_head->name##_next; \
	if (ctx == ke->name##_list_tail) ke->name##_list_tail = ke->name##_list_tail->name##_prev; \
	if (ctx->name##_prev) ctx->name##_prev->name##_next = ctx->name##_next; \
	if (ctx->name##_next) ctx->name##_next->name##_prev = ctx->name##_prev; \
	ctx->name##_prev = ctx->name##_next = NULL; \
	ke->name##_count--; }

#define LIST_MEMBER(name, ctx) \
	(ke->name##_list_head == ctx || ctx->name##_prev || ctx->name##_next)


void ke_list_insert_head(enum ke_list_enum list, struct ctx_t *ctx)
{
	assert(!ke_list_member(list, ctx));
	switch (list) {
	case ke_list_context: LIST_INSERT_HEAD(context, ctx); break;
	case ke_list_running: LIST_INSERT_HEAD(running, ctx); break;
	case ke_list_finished: LIST_INSERT_HEAD(finished, ctx); break;
	case ke_list_zombie: LIST_INSERT_HEAD(zombie, ctx); break;
	case ke_list_suspended: LIST_INSERT_HEAD(suspended, ctx); break;
	case ke_list_alloc: LIST_INSERT_HEAD(alloc, ctx); break;
	}
}


void ke_list_insert_tail(enum ke_list_enum list, struct ctx_t *ctx)
{
	assert(!ke_list_member(list, ctx));
	switch (list) {
	case ke_list_context: LIST_INSERT_TAIL(context, ctx); break;
	case ke_list_running: LIST_INSERT_TAIL(running, ctx); break;
	case ke_list_finished: LIST_INSERT_TAIL(finished, ctx); break;
	case ke_list_zombie: LIST_INSERT_TAIL(zombie, ctx); break;
	case ke_list_suspended: LIST_INSERT_TAIL(suspended, ctx); break;
	case ke_list_alloc: LIST_INSERT_TAIL(alloc, ctx); break;
	}
}


void ke_list_remove(enum ke_list_enum list, struct ctx_t *ctx)
{
	assert(ke_list_member(list, ctx));
	switch (list) {
	case ke_list_context: LIST_REMOVE(context, ctx); break;
	case ke_list_running: LIST_REMOVE(running, ctx); break;
	case ke_list_finished: LIST_REMOVE(finished, ctx); break;
	case ke_list_zombie: LIST_REMOVE(zombie, ctx); break;
	case ke_list_suspended: LIST_REMOVE(suspended, ctx); break;
	case ke_list_alloc: LIST_REMOVE(alloc, ctx); break;
	}
}


int ke_list_member(enum ke_list_enum list, struct ctx_t *ctx)
{
	switch (list) {
	case ke_list_context: return LIST_MEMBER(context, ctx);
	case ke_list_running: return LIST_MEMBER(running, ctx);
	case ke_list_finished: return LIST_MEMBER(finished, ctx);
	case ke_list_zombie: return LIST_MEMBER(zombie, ctx);
	case ke_list_suspended: return LIST_MEMBER(suspended, ctx);
	case ke_list_alloc: return LIST_MEMBER(alloc, ctx);
	}
	return 0;
}


#undef LIST_INSERT
#undef LIST_REMOVE
#undef LIST_MEMBER


/* Return a counter of microseconds. */
uint64_t ke_timer()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t) tv.tv_sec * 1000000 + tv.tv_usec - ke_init_time;
}


/* Schedule a call to 'ke_process_events' */
void ke_process_events_schedule()
{
	pthread_mutex_lock(&ke->process_events_mutex);
	ke->process_events_force = 1;
	pthread_mutex_unlock(&ke->process_events_mutex);
}


/* Function that suspends the host thread waiting for an event to occur.
 * When the event finally occurs (i.e., before the function finishes, a
 * call to 'ke_process_events' is scheduled.
 * The argument 'arg' is the associated guest context. */
void *ke_host_thread_suspend(void *arg)
{
	struct ctx_t *ctx = (struct ctx_t *) arg;
	uint64_t now = ke_timer();

	/* Detach this thread - we don't want the parent to have to join it to release
	 * its resources. The thread termination can be observed by atomically checking
	 * the 'ctx->host_thread_suspend_active' flag. */
	pthread_detach(pthread_self());

	/* Context suspended in 'poll' system call */
	if (ctx_get_status(ctx, ctx_nanosleep)) {
		
		uint64_t timeout;
		
		/* Calculate remaining sleep time in microseconds */
		timeout = ctx->wakeup_time > now ? ctx->wakeup_time - now : 0;
		usleep(timeout);
	
	} else if (ctx_get_status(ctx, ctx_poll)) {

		struct fd_t *fd;
		struct pollfd host_fds;
		int err, timeout;
		
		/* Get file descriptor */
		fd = fdt_entry_get(ctx->fdt, ctx->wakeup_fd);
		if (!fd)
			fatal("syscall 'poll': invalid 'wakeup_fd'");

		/* Calculate timeout for host call in milliseconds from now */
		if (!ctx->wakeup_time)
			timeout = -1;
		else if (ctx->wakeup_time < now)
			timeout = 0;
		else
			timeout = (ctx->wakeup_time - now) / 1000;

		/* Perform blocking host 'poll' */
		host_fds.fd = fd->host_fd;
		host_fds.events = ((ctx->wakeup_events & 4) ? POLLOUT : 0) | ((ctx->wakeup_events & 1) ? POLLIN : 0);
		err = poll(&host_fds, 1, timeout);
		if (err < 0)
			fatal("syscall 'poll': unexpected error in host 'poll'");
	
	} else if (ctx_get_status(ctx, ctx_read)) {
		
		struct fd_t *fd;
		struct pollfd host_fds;
		int err;

		/* Get file descriptor */
		fd = fdt_entry_get(ctx->fdt, ctx->wakeup_fd);
		if (!fd)
			fatal("syscall 'read': invalid 'wakeup_fd'");

		/* Perform blocking host 'poll' */
		host_fds.fd = fd->host_fd;
		host_fds.events = POLLIN;
		err = poll(&host_fds, 1, -1);
		if (err < 0)
			fatal("syscall 'read': unexpected error in host 'poll'");
	
	} else if (ctx_get_status(ctx, ctx_write)) {
		
		struct fd_t *fd;
		struct pollfd host_fds;
		int err;

		/* Get file descriptor */
		fd = fdt_entry_get(ctx->fdt, ctx->wakeup_fd);
		if (!fd)
			fatal("syscall 'write': invalid 'wakeup_fd'");

		/* Perform blocking host 'poll' */
		host_fds.fd = fd->host_fd;
		host_fds.events = POLLOUT;
		err = poll(&host_fds, 1, -1);
		if (err < 0)
			fatal("syscall 'write': unexpected error in host 'write'");

	}

	/* Event occurred - thread finishes */
	pthread_mutex_lock(&ke->process_events_mutex);
	ke->process_events_force = 1;
	ctx->host_thread_suspend_active = 0;
	pthread_mutex_unlock(&ke->process_events_mutex);
	return NULL;
}


/* Function that suspends the host thread waiting for a timer to expire,
 * and then schedules a call to 'ke_process_events'. */
void *ke_host_thread_timer(void *arg)
{
	struct ctx_t *ctx = (struct ctx_t *) arg;
	uint64_t now = ke_timer();
	struct timespec ts;
	uint64_t sleep_time;  /* In usec */

	/* Detach this thread - we don't want the parent to have to join it to release
	 * its resources. The thread termination can be observed by thread-safely checking
	 * the 'ctx->host_thread_timer_active' flag. */
	pthread_detach(pthread_self());

	/* Calculate sleep time, and sleep only if it is greater than 0 */
	if (ctx->host_thread_timer_wakeup > now) {
		sleep_time = ctx->host_thread_timer_wakeup - now;
		ts.tv_sec = sleep_time / 1000000;
		ts.tv_nsec = (sleep_time % 1000000) * 1000;  /* nsec */
		nanosleep(&ts, NULL);
	}

	/* Timer expired, schedule call to 'ke_process_events' */
	pthread_mutex_lock(&ke->process_events_mutex);
	ke->process_events_force = 1;
	ctx->host_thread_timer_active = 0;
	pthread_mutex_unlock(&ke->process_events_mutex);
	return NULL;
}


/* Check for events detected in spawned host threads, like waking up contexts or
 * sending signals.
 * The list is only processed if flag 'ke->process_events_force' is set. */
void ke_process_events()
{
	struct ctx_t *ctx, *next;
	uint64_t now = ke_timer();
	
	/* Check if events need actually be checked. */
	pthread_mutex_lock(&ke->process_events_mutex);
	if (!ke->process_events_force) {
		pthread_mutex_unlock(&ke->process_events_mutex);
		return;
	}
	
	/* By default, no subsequent call to 'ke_process_events' is assumed */
	ke->process_events_force = 0;

	/*
	 * LOOP 1
	 * Look at the list of suspended contexts and try to find
	 * one that needs to be woken up.
	 */
	for (ctx = ke->suspended_list_head; ctx; ctx = next) {

		/* Save next */
		next = ctx->suspended_next;

		/* Context is suspended in 'nanosleep' system call. */
		if (ctx_get_status(ctx, ctx_nanosleep))
		{
			uint32_t rmtp = ctx->regs->ecx;
			uint64_t zero = 0;
			uint32_t sec, usec;
			uint64_t diff;

			/* If 'ke_host_thread_suspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Timeout expired */
			if (ctx->wakeup_time <= now) {
				if (rmtp)
					mem_write(ctx->mem, rmtp, 8, &zero);
				syscall_debug("syscall 'nanosleep' - continue (pid %d)\n", ctx->pid);
				syscall_debug("  return=0x%x\n", ctx->regs->eax);
				ctx_clear_status(ctx, ctx_suspended | ctx_nanosleep);
				continue;
			}

			/* Context received a signal */
			if (ctx->signal_masks->pending & ~ctx->signal_masks->blocked) {
				if (rmtp) {
					diff = ctx->wakeup_time - now;
					sec = diff / 1000000;
					usec = diff % 1000000;
					mem_write(ctx->mem, rmtp, 4, &sec);
					mem_write(ctx->mem, rmtp + 4, 4, &usec);
				}
				ctx->regs->eax = -EINTR;
				syscall_debug("syscall 'nanosleep' - interrupted by signal (pid %d)\n", ctx->pid);
				ctx_clear_status(ctx, ctx_suspended | ctx_nanosleep);
				continue;
			}

			/* No event available, launch 'ke_host_thread_suspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, ke_host_thread_suspend, ctx))
				fatal("syscall 'poll': could not create child thread");
			continue;
		}

		/* Context suspended in 'rt_sigsuspend' system call */
		if (ctx_get_status(ctx, ctx_sigsuspend))
		{
			/* Context received a signal */
			if (ctx->signal_masks->pending & ~ctx->signal_masks->blocked) {
				signal_handler_check_intr(ctx);
				ctx->signal_masks->blocked = ctx->signal_masks->backup;
				syscall_debug("syscall 'rt_sigsuspend' - interrupted by signal (pid %d)\n", ctx->pid);
				ctx_clear_status(ctx, ctx_suspended | ctx_sigsuspend);
				continue;
			}

			/* No event available. The context will never awake on its own, so no
			 * 'ke_host_thread_suspend' is necessary. */
			continue;
		}

		/* Context suspended in 'poll' system call */
		if (ctx_get_status(ctx, ctx_poll))
		{
			uint32_t prevents = ctx->regs->ebx + 6;
			uint16_t revents = 0;
			struct fd_t *fd;
			struct pollfd host_fds;
			int err;

			/* If 'ke_host_thread_suspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Get file descriptor */
			fd = fdt_entry_get(ctx->fdt, ctx->wakeup_fd);
			if (!fd)
				fatal("syscall 'poll': invalid 'wakeup_fd'");

			/* Context received a signal */
			if (ctx->signal_masks->pending & ~ctx->signal_masks->blocked) {
				signal_handler_check_intr(ctx);
				syscall_debug("syscall 'poll' - interrupted by signal (pid %d)\n", ctx->pid);
				ctx_clear_status(ctx, ctx_suspended | ctx_poll);
				continue;
			}

			/* Perform host 'poll' call */
			host_fds.fd = fd->host_fd;
			host_fds.events = ((ctx->wakeup_events & 4) ? POLLOUT : 0) | ((ctx->wakeup_events & 1) ? POLLIN : 0);
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'poll': unexpected error in host 'poll'");

			/* POLLOUT event available */
			if (ctx->wakeup_events & host_fds.revents & POLLOUT) {
				revents = POLLOUT;
				mem_write(ctx->mem, prevents, 2, &revents);
				ctx->regs->eax = 1;
				syscall_debug("syscall poll - continue (pid %d) - POLLOUT occurred in file\n", ctx->pid);
				syscall_debug("  retval=%d\n", ctx->regs->eax);
				ctx_clear_status(ctx, ctx_suspended | ctx_poll);
				continue;
			}

			/* POLLIN event available */
			if (ctx->wakeup_events & host_fds.revents & POLLIN) {
				revents = POLLIN;
				mem_write(ctx->mem, prevents, 2, &revents);
				ctx->regs->eax = 1;
				syscall_debug("syscall poll - continue (pid %d) - POLLIN occurred in file\n", ctx->pid);
				syscall_debug("  retval=%d\n", ctx->regs->eax);
				ctx_clear_status(ctx, ctx_suspended | ctx_poll);
				continue;
			}

			/* Timeout expired */
			if (ctx->wakeup_time && ctx->wakeup_time < now) {
				revents = 0;
				mem_write(ctx->mem, prevents, 2, &revents);
				syscall_debug("syscall poll - continue (pid %d) - time out\n", ctx->pid);
				syscall_debug("  return=0x%x\n", ctx->regs->eax);
				ctx_clear_status(ctx, ctx_suspended | ctx_poll);
				continue;
			}

			/* No event available, launch 'ke_host_thread_suspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, ke_host_thread_suspend, ctx))
				fatal("syscall 'poll': could not create child thread");
			continue;
		}


		/* Context suspended in a 'write' system call  */
		if (ctx_get_status(ctx, ctx_write))
		{
			struct fd_t *fd;
			int count, err;
			uint32_t pbuf;
			void *buf;
			struct pollfd host_fds;

			/* If 'ke_host_thread_suspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Context received a signal */
			if (ctx->signal_masks->pending & ~ctx->signal_masks->blocked) {
				signal_handler_check_intr(ctx);
				syscall_debug("syscall 'write' - interrupted by signal (pid %d)\n", ctx->pid);
				ctx_clear_status(ctx, ctx_suspended | ctx_write);
				continue;
			}

			/* Get file descriptor */
			fd = fdt_entry_get(ctx->fdt, ctx->wakeup_fd);
			if (!fd)
				fatal("syscall 'write': invalid 'wakeup_fd'");

			/* Check if data is ready in file by polling it */
			host_fds.fd = fd->host_fd;
			host_fds.events = POLLOUT;
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'write': unexpected error in host 'poll'");

			/* If data is ready in the file, wake up context */
			if (host_fds.revents) {
				pbuf = ctx->regs->ecx;
				count = ctx->regs->edx;
				buf = malloc(count);
				mem_read(ctx->mem, pbuf, count, buf);

				count = write(fd->host_fd, buf, count);
				if (count < 0)
					fatal("syscall 'write': unexpected error in host 'write'");

				ctx->regs->eax = count;
				free(buf);

				syscall_debug("syscall write - continue (pid %d)\n", ctx->pid);
				syscall_debug("  return=0x%x\n", ctx->regs->eax);
				ctx_clear_status(ctx, ctx_suspended | ctx_write);
				continue;
			}

			/* Data is not ready to be written - launch 'ke_host_thread_suspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, ke_host_thread_suspend, ctx))
				fatal("syscall 'write': could not create child thread");
			continue;
		}

		/* Context suspended in 'read' system call */
		if (ctx_get_status(ctx, ctx_read))
		{
			struct fd_t *fd;
			uint32_t pbuf;
			int count, err;
			void *buf;
			struct pollfd host_fds;

			/* If 'ke_host_thread_suspend' is still running for this context, do nothing. */
			if (ctx->host_thread_suspend_active)
				continue;

			/* Context received a signal */
			if (ctx->signal_masks->pending & ~ctx->signal_masks->blocked) {
				signal_handler_check_intr(ctx);
				syscall_debug("syscall 'read' - interrupted by signal (pid %d)\n", ctx->pid);
				ctx_clear_status(ctx, ctx_suspended | ctx_read);
				continue;
			}

			/* Get file descriptor */
			fd = fdt_entry_get(ctx->fdt, ctx->wakeup_fd);
			if (!fd)
				fatal("syscall 'read': invalid 'wakeup_fd'");

			/* Check if data is ready in file by polling it */
			host_fds.fd = fd->host_fd;
			host_fds.events = POLLIN;
			err = poll(&host_fds, 1, 0);
			if (err < 0)
				fatal("syscall 'read': unexpected error in host 'poll'");

			/* If data is ready, perform host 'read' call and wake up */
			if (host_fds.revents) {
				pbuf = ctx->regs->ecx;
				count = ctx->regs->edx;
				buf = malloc(count);
				
				count = read(fd->host_fd, buf, count);
				if (count < 0)
					fatal("syscall 'read': unexpected error in host 'read'");

				ctx->regs->eax = count;
				mem_write(ctx->mem, pbuf, count, buf);
				free(buf);

				syscall_debug("syscall 'read' - continue (pid %d)\n", ctx->pid);
				syscall_debug("  return=0x%x\n", ctx->regs->eax);
				ctx_clear_status(ctx, ctx_suspended | ctx_read);
				continue;
			}

			/* Data is not ready. Launch 'ke_host_thread_suspend' again */
			ctx->host_thread_suspend_active = 1;
			if (pthread_create(&ctx->host_thread_suspend, NULL, ke_host_thread_suspend, ctx))
				fatal("syscall 'read': could not create child thread");
			continue;
		}

		/* Context suspended in a 'waitpid' system call */
		if (ctx_get_status(ctx, ctx_waitpid))
		{
			struct ctx_t *child;
			uint32_t pstatus;

			/* A zombie child is available to 'waitpid' it */
			child = ctx_get_zombie(ctx, ctx->wakeup_pid);
			if (child) {

				/* Continue with 'waitpid' system call */
				pstatus = ctx->regs->ecx;
				ctx->regs->eax = child->pid;
				if (pstatus)
					mem_write(ctx->mem, pstatus, 4, &child->exit_code);
				ctx_set_status(child, ctx_finished);

				syscall_debug("syscall waitpid - continue (pid %d)\n", ctx->pid);
				syscall_debug("  return=0x%x\n", ctx->regs->eax);
				ctx_clear_status(ctx, ctx_suspended | ctx_waitpid);
				continue;
			}

			/* No event available. Since this context won't awake on its own, no
			 * 'ke_host_thread_suspend' is needed. */
			continue;
		}
	}


	/*
	 * LOOP 2
	 * Check list of all contexts for expired timers.
	 */
	for (ctx = ke->context_list_head; ctx; ctx = ctx->context_next)
	{
		int sig[3] = { 14, 26, 27 };  /* SIGALRM, SIGVTALRM, SIGPROF */
		int i;

		/* If there is already a 'ke_host_thread_timer' running, do nothing. */
		if (ctx->host_thread_timer_active)
			continue;

		/* Check for any expired 'itimer': itimer_value < now
		 * In this case, send corresponding signal to process.
		 * Then calculate next 'itimer' occurrence: itimer_value = now + itimer_interval */
		for (i = 0; i < 3; i++ ) {
			
			/* Timer inactive or not expired yet */
			if (!ctx->itimer_value[i] || ctx->itimer_value[i] > now)
				continue;

			/* Timer expired - send a signal.
			 * The target process might be suspended, so the host thread is canceled, and a new
			 * call to 'ke_process_events' is scheduled. Since 'ke_process_events_mutex' is
			 * already locked, the thread-unsafe version of 'ctx_host_thread_suspend_cancel' is used. */
			__ctx_host_thread_suspend_cancel(ctx);
			ke->process_events_force = 1;
			sim_sigset_add(&ctx->signal_masks->pending, sig[i]);

			/* Calculate next occurrence */
			ctx->itimer_value[i] = 0;
			if (ctx->itimer_interval[i])
				ctx->itimer_value[i] = now + ctx->itimer_interval[i];
		}

		/* Calculate the time when next wakeup occurs. */
		ctx->host_thread_timer_wakeup = 0;
		for (i = 0; i < 3; i++) {
			if (!ctx->itimer_value[i])
				continue;
			assert(ctx->itimer_value[i] >= now);
			if (!ctx->host_thread_timer_wakeup || ctx->itimer_value[i] < ctx->host_thread_timer_wakeup)
				ctx->host_thread_timer_wakeup = ctx->itimer_value[i];
		}

		/* If a new timer was set, launch 'ke_host_thread_timer' again */
		if (ctx->host_thread_timer_wakeup) {
			ctx->host_thread_timer_active = 1;
			if (pthread_create(&ctx->host_thread_timer, NULL, ke_host_thread_timer, ctx))
				fatal("%s: could not create child thread", __FUNCTION__);
		}
	}


	/*
	 * LOOP 3
	 * Process pending signals in running contexts to launch signal handlers
	 */
	for (ctx = ke->running_list_head; ctx; ctx = ctx->running_next)
	{
		signal_handler_check(ctx);
	}

	
	/* Unlock */
	pthread_mutex_unlock(&ke->process_events_mutex);
}


/*
 * Virtual Memory Implementation
 */

#include <stdio.h>
#include "m2skernel.h"

void vmem_add_page(ptentry_t *page);
ptentry_t* run_clock_policy();
void perform_page_in(pageop_t op);
void perform_page_out(pageop_t op);

/*
 * Address Translation
 */

uint32_t get_physical(struct page_table * P,uint32_t vaddr)
{
	uint32_t index, tag, paddr, offset, phystag;
	int valid_bit;
	tag = vaddr & ~(VIRT_MEM_PAGESIZE - 1);
	offset = vaddr & (VIRT_MEM_PAGESIZE -1);
	index = (vaddr >> VIRT_MEM_LOGPAGESIZE) % MEM_PAGE_COUNT;
	
	valid_bit = (P->translation[index]).valid_bit;
	
	//function page fault should be called if not valid...
	
	phystag = (P->translation[index]).paddr; 
	
	paddr = phystag << VIRT_MEM_LOGPAGESIZE + offset;
	return paddr;
}

uint32_t get_logical(struct page_table * P,uint32_t paddr)
{
	int offset = paddr & (VIRT_MEM_LOGPAGESIZE -1);
	uint32_t i;
	for(i=0;i<size;i++)
	{
		if(P->translation[i]->physical_addr == paddr)
			return i << VIRT_MEM_LOGPAGESIZE + offset;
	}
}

ptentry_t * get_page_table_entry(struct page_table * P,uint32_t vaddr)
{
	uint32_t index, tag,paddr;
	tag = vaddr & ~(VIRT_MEM_PAGESIZE - 1);
	index = (vaddr >> VIRT_MEM_LOGPAGESIZE) % MEM_PAGE_COUNT;
	return &(P->translation[index]);
}

uint32_t make_an_entry(struct page_table * P,uint32_t vaddr,uint32_t paddr)
{
	offset = vadrr & (VIRT_MEM_PAGESIZE -1);
	index = (vaddr >> VIRT_MEM_LOGPAGESIZE) % MEM_PAGE_COUNT;
	
	ptentry_t * E;
	E = calloc(1,size(ptentry_t));
	E->valid_bit = 1;
	E->dirtybit = 0;
	E->physical_addr = paddr;
	E->swap_disk_num = 1;
	E->swap_offset = offset;
	
	P->translation[index] = 
}


/*
 * Page Replacement
 */

void vmem_load_page(ptentry_t *entry) {
	printf("Starting page load for vaddr: %d\n", entry->vaddr);

	pageop_t pagein_op;
	pagein_op.operation = OPERATION_PAGE_IN;
	pagein_op.vaddr = entry->vaddr;
	pagein_op.pte = entry;

	// Check for free frames
	if (isa_ctx->mem->free_frames_size > 0) {
		pagein_op.paddr = isa_ctx->mem->free_frames[isa_ctx->mem->free_frames_size - 1];
		vmem_add_page(pagein_op.pte);
		printf("Loading into free_frame: %d\n", pagein_op.paddr);
	}
	else
	{
		ptentry_t *pte = run_clock_policy(entry);
		pagein_op.paddr = pte->paddr;
			
		pageop_t pageout_op;
		pageout_op.operation = OPERATION_PAGE_OUT;
		pageout_op.pte = pte;
		pageout_op.vaddr = pte->vaddr;
		pageout_op.paddr = pte->paddr; // No physical address for pageout
		perform_page_out(pageout_op);
	}
	
	perform_page_in(pagein_op);
}

void* read_swap(uint32_t vaddr) {
	return NULL;
}

void write_swap(uint32_t vaddr, void* data) {
	
}

void perform_page_in(pageop_t op) {
	printf("Page in: %d -> %d\n", op.vaddr, op.paddr);
	void* page = read_swap(op.vaddr);
	// TODO Store page in ctx->mem at position corresponding to paddr
	op.pte->valid_bit = 1;
	op.pte->paddr = op.paddr;
	op.pte->dirtybit = 0;
	isa_ctx->mem->free_frames_size--;
}

void perform_page_out(pageop_t op) {
	printf("Page out: %d from %d\n", op.vaddr, op.paddr);
	if (op.pte->dirtybit) {
		void* data;
		// TODO load page data in 'data'
		write_swap(op.vaddr, data);
	}
	op.pte->valid_bit = 0;
	isa_ctx->mem->free_frames[isa_ctx->mem->free_frames_size] = op.paddr;
	isa_ctx->mem->free_frames_size++;
}

/*
 * Page Replacement Policy (One Hand Clock Algorithm)
 */

void vmem_add_page(ptentry_t *page) {
	isa_mem->valid_pages[isa_mem->valid_pages_size] = page;
	isa_mem->valid_pages_size++;
}

void inc_pointer() {
	isa_mem->clock_pointer++;
	if (isa_mem->clock_pointer == isa_mem->valid_pages_size)
		isa_mem->clock_pointer = 0;
}

void display_state() {
    int i;
    for (i = 0; i < isa_mem->valid_pages_size; i++) {
        if (i == isa_mem->clock_pointer)
            printf("*");
        printf("[%d,%d]\t", isa_mem->valid_pages[i]->vaddr, isa_mem->valid_pages[i]->used);
    }
    printf("\n");
}

ptentry_t* run_clock_policy(ptentry_t* newpage) {
    printf("Starting page replacement, initial state:\n");
    display_state();
    ptentry_t **page_list = isa_mem->valid_pages;
	while (1) {
		int clock_pointer = isa_mem->clock_pointer;
		if (!page_list[clock_pointer]->used) {
			ptentry_t * page_to_replace = page_list[clock_pointer];
			page_list[clock_pointer] = newpage;
			inc_pointer();
            printf("OUT: %d,  IN: %d\n", page_to_replace->vaddr, newpage->vaddr);
            return page_to_replace;
		} else {
			page_list[clock_pointer]->used = 0;
			inc_pointer();
		}
        display_state();
	}
}

