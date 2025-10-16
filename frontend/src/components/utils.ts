import { toast } from "react-toastify";

export const handleSuccess = (msg: string): void => {
  toast.success(msg, {
    position: "top-right",
  });
};

export const handleError = (msg: string | Error | unknown): void => {
  const message = typeof msg === 'string' ? msg : msg instanceof Error ? msg.message : 'An error occurred';
  toast.error(message, {
    position: "top-right",
  });
};