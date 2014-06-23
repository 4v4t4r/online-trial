$(document).ready(function() {
    $('#f_register').bootstrapValidator({
        message: 'This value is not valid',
        feedbackIcons: {
            valid: 'glyphicon glyphicon-ok',
            invalid: 'glyphicon glyphicon-remove'
        },
        live: 'enabled',
        fields: {
            name: {
                validators: {
                    notEmpty: { message: 'Field cannot be empty' },
                    regexp: { regexp: '^[^ ]+ [^ ]+', message: 'Please enter your FULL name' }
                }
            },
            email: {
                validators: {
                    notEmpty: { message: 'Field canot be empty' },
                    emailAddress: { message: 'Please enter a valid email address' },
                    remote: { message: 'Already registered. Click <a href="javascript:send_reminder()">here</a> to retrieve your trial details.',
                              url: '/trials/_/checkemail' }
                }
            }
        }
    });
});

function on_dyn_poll_result(data, status, xhr)
{
    if (data.status != 'READY') {
        var span = $('#sp_status');
        var current = span.html();
        if (current.startsWith(data.status)) {
            var ndots = current.length - data.status.length;
            ndots = (ndots == 5) ? 0 : ndots + 1;
        } else
            ndots = 0;
        span.html(data.status + '.'.repeat(ndots));
        $('#sp_ssh_addr').html('waiting' + '.'.repeat(ndots));
        $('#sp_http_url').html('waiting' + '.'.repeat(ndots));
        $('#sp_vnc_url').html('waiting' + '.'.repeat(ndots));
        window.setTimeout(function() { poll_dyn(data.id); }, 1000);
    } else {
        $('#sp_status').html(data.status);
        $('#sp_ssh_addr').html(data.ssh_addr);
        $('#sp_http_url').html('<a href="' + data.http_url + '">Open management interface</a>');
        $('#sp_vnc_url').html('<a href="/trials/' + data.id + '/vnc">Open VNC Console</a>');
        $('#p_intro').hide();
        $('#p_ready').show();
    }
}

function poll_dyn(id)
{
    var url = '/trials/' + id + '/dyn';
    $.ajax(url, {type: 'GET', dataType: 'json', success: on_dyn_poll_result});
}

function on_reminder_result(data, status, xhr)
{
    $('#reminder_modal .modal-body').html('Email was sent succesfully');
    $('#reminder_modal').modal('show');
}

function on_reminder_error(xhr, status, error)
{
    $('#reminder_modal .modal-body').html('Error sending email');
    $('#reminder_modal').modal('show');
}

function send_reminder()
{
    var email = $('#f_register input[name=email]').val();
    $.ajax('/trials/_/remind', {data: {email: email}, type: 'POST',
                                success: on_reminder_result,  error: on_reminder_error});
}
