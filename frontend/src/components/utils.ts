import { toast, ToastOptions } from "react-toastify";

const toastConfig: ToastOptions = {
  position: "top-right",
};

export const handleSuccess = (msg: string): void => {
  toast.success(msg, toastConfig);
};

export const handleError = (msg: string): void => {
  toast.error(msg, toastConfig);
};